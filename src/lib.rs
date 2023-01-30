use std::{sync::Mutex, collections::HashMap, borrow::BorrowMut};
use pgx::{prelude::*, AnyElement, IntoDatum, FromDatum, pg_sys::Oid};
use oso::{Oso, PolarValue, ExtClassBuilder, Class, ToPolar, Instance};
use lazy_static::lazy_static;
use askama::Template;
use anyhow::anyhow;

pgx::pg_module_magic!();

lazy_static! {
    static ref OSO: Mutex<Oso> = {
        let oso = Oso::new();
        Mutex::new(oso)
    };
    static ref REGISTERED_TYPES: Mutex<HashMap<Oid, Class>> = Mutex::new(HashMap::new());
}

struct ToPolarWrapPolarValue(PolarValue);

impl ToPolar for ToPolarWrapPolarValue {
    fn to_polar(self) -> PolarValue {
        self.0
    }
}

#[pg_extern]
fn oso_reload() -> Result<(), anyhow::Error> {
    let mut oso = OSO.lock().unwrap();
    int_oso_reload(oso.borrow_mut())?;
    Ok(())
}

fn int_oso_reload(oso: &mut Oso) -> Result<(), anyhow::Error> {
    Spi::connect(|client| {
        oso.clear_rules()?;
        let sources: Vec<&str> = client.select("select rule from oso_rules order by ord", None, None)?
            .map(|ht| {ht.get(1).unwrap().unwrap()})
            .collect();
        oso.load_strs(sources)?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

// table has to be public in order for function executors to load
extension_sql!(
    r#"
        create table oso_rules (rule text not null, ord int not null);
        grant select on oso_rules to public;
        create function oso_reload_wrap() returns trigger as $$
        begin
        return null;
        end
        $$ language plpgsql;

        create trigger oso_reload after insert or update or delete on oso_rules for each statement execute function oso_reload_wrap();
    "#,
    name = "bootstrap_raw",
    requires = [oso_reload],
);

/// Function to configure oso based row level security on a table
#[pg_extern]
fn oso_configure_rls(table_name: &str) -> Result<(), anyhow::Error> {
    Spi::connect(|mut client| {
        let table_cols: Vec<&str> = client.select(
            "select attname::text from pg_attribute att join pg_class cls on cls.oid = att.attrelid and cls.relname = $1 and att.attnum > 0 order by attnum", 
            None, Some(vec![(PgBuiltInOids::TEXTOID.oid(), table_name.into_datum())]))?
        .map(|ht| {ht.get::<&str>(1).unwrap().unwrap()}) // I should be able to rely on pg_attribute
        .collect();

        client.update(&AlterTableEnableRls{ table_name }.render()?, None, None)?; 
        // Actions match postgres' terminology
        for action in &["insert","select", "update", "delete"] {
            client.update(&DropPolicy{table_name, action}.render()?, None, None)?;
        }
        client.update(&CreateInsertPolicy{table_name, table_cols: table_cols.as_slice()}.render()?, None,None)?;
        client.update(&CreateSelectPolicy{table_name, table_cols: table_cols.as_slice()}.render()?, None,None)?;
        client.update(&CreateUpdatePolicy{table_name, table_cols: table_cols.as_slice()}.render()?, None,None)?;
        client.update(&CreateDeletePolicy{table_name, table_cols: table_cols.as_slice()}.render()?, None,None)?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[derive(Template)]
#[template(path = "alter_table_enable_rls.sql", escape = "none")]
struct AlterTableEnableRls<'a> {table_name: &'a str}
#[derive(Template)]
#[template(path = "drop_policy.sql", escape = "none")]
struct DropPolicy<'a> {table_name: &'a str, action: &'a str}
#[derive(Template)]
#[template(path = "create_select_policy.sql", escape = "none")]
struct CreateSelectPolicy<'a> {table_name: &'a str, table_cols: &'a [&'a str]}
#[derive(Template)]
#[template(path = "create_insert_policy.sql", escape = "none")]
struct CreateInsertPolicy<'a> {table_name: &'a str, table_cols: &'a [&'a str]}
#[derive(Template)]
#[template(path = "create_update_policy.sql", escape = "none")]
struct CreateUpdatePolicy<'a> {table_name: &'a str, table_cols: &'a [&'a str]}
#[derive(Template)]
#[template(path = "create_delete_policy.sql", escape = "none")]
struct CreateDeletePolicy<'a> {table_name: &'a str, table_cols: &'a [&'a str]}

#[pg_extern]
fn oso_is_allowed(subject: &str, action: &str, object: AnyElement) -> Result<bool, anyhow::Error> {
    // PgHeapTuple lets us actually access fields from 'object'
    let ht = unsafe {
        PgHeapTuple::from_datum(object.datum(), object.datum().is_null())
    }.ok_or(anyhow!("failed to convert object to PgHeapTuple"))?;
    
    // Register our type with Oso iff we haven't
    let mut hm = REGISTERED_TYPES.lock().unwrap();
    let mut oso = OSO.lock().unwrap();
    if !hm.contains_key(&object.oid()) {

        // I'm sure there's a typecache but we don't seem to have access via pg_sys
        let class_name = Spi::connect(|client| {
            client
                .select(
                    // Cast is required, typname is of type 'name' which pgx mishandles!
                    "SELECT typname::text FROM pg_type WHERE oid = $1",
                    None,
                    Some(vec![(PgBuiltInOids::OIDOID.oid(), object.oid().into_datum())]),
                )?
                .first()
                .get_one::<String>()
        })?.ok_or(anyhow!("failed to get typename from oid {}", object.oid()))?;

        let mut cb = ExtClassBuilder::new(object.oid().as_u32().into(), class_name);
        for (_, attinfo) in ht.attributes() {
            let name: String = attinfo.name().to_string();
            let name2 = name.clone();
            cb = cb.add_attribute_getter(&name, move |instance: &HashMap<String, PolarValue>| {
                let get = instance.get(&name2).unwrap();
                ToPolarWrapPolarValue(get.clone())
            });
        }
        let class = cb.build();

        oso.register_class(class.clone())?;
        hm.insert(object.oid(), class);
        // types have to be registered before policies, so reload our policy if we had to load a new class
        // https://docs.osohq.com/any/project/changelogs/2020-08-11.html
        int_oso_reload(oso.borrow_mut())?;
    }

    // Collect into values we can supply to Polar later
    let hm_values: HashMap<String, PolarValue> = ht.attributes().map(|(attno, attinfo)| {
        let k = attinfo.name().to_string();
        let v: PolarValue = match attinfo.type_oid() {
            // TODO handle more types
            PgOid::BuiltIn(PgBuiltInOids::TEXTOID) => {
                let st = ht.get_by_index::<String>(attno)?;
                // What is a null PolarValue? Is there one? I can't find it
                let st = st.unwrap_or("".to_string());
                Ok(st.to_polar())
            },
            PgOid::BuiltIn(PgBuiltInOids::TIMESTAMPTZOID) => {
                let ts = ht.get_by_index::<TimestampWithTimeZone>(attno)?;
                let ts = ts.map(|tswz| {format!("{:?}", tswz)});
                Ok(ts.to_polar())
            },
            x => Err(anyhow!("unsupported type_oid {:?}", x))
        }?;
        Ok::<(String,PolarValue), anyhow::Error>((k, v))
    })
    .filter_map(|x: Result<(String,PolarValue), _>| {x.ok()})
    .collect();
    let instance = Instance::new_ext(hm_values, object.oid().as_u32().into(), "foo"); // Debug name isn't important.
    let allowed = oso.is_allowed(subject, action, ToPolarWrapPolarValue(PolarValue::Instance(instance)))?;
    Ok(allowed)
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    // use pgx::prelude::*;

    // TODO how to test this?
    // I can't use SPI to test because we're executing as a super-user, and also can't specify a user to run queries as.
    // I _could_ just execute the function instead of testing the actual RLS policies, but it's not the same.
    // 
    // #[pg_test]
    // fn test_hello_rls_oso() {
    //     assert_eq!("Hello, rls_oso", crate::hello_rls_oso());
    // }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
