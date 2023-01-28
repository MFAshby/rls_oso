use std::{sync::Mutex, collections::HashMap};
use pgx::{prelude::*, AnyElement, IntoDatum, FromDatum, pg_sys::Oid};
use oso::{Oso, PolarValue, ExtClassBuilder, Class, ToPolar, Instance};
use lazy_static::lazy_static;
use askama::Template;

pgx::pg_module_magic!();

static POLICY: &'static str = r#"allow(subject, "select", object: comments) if object.author = subject;"#;

lazy_static! {
    static ref OSO: Mutex<Oso> = {
        let mut oso = Oso::new();
        oso.load_str(POLICY).unwrap();
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

/// Function to configure oso based row level security on a table
#[pg_extern]
fn oso_configure_rls(table_name: &str) {
    Spi::connect(|mut client| {
        let table_cols: Vec<&str> = client.select("select attname::text from pg_attribute att join pg_class cls on cls.oid = att.attrelid and cls.relname = $1 and att.attnum > 0 order by attnum", None, 
            Some(vec![(PgBuiltInOids::TEXTOID.oid(), table_name.into_datum())])).unwrap()
        .map(|ht| {ht.get::<&str>(1).unwrap().unwrap()})
        .collect();

        client.update(&AlterTableEnableRls{ table_name }.render().unwrap(), None, None).unwrap(); 
        // Actions match postgres' terminology
        for action in &["insert","select", "update", "delete"] {
            client.update(&DropPolicy{table_name, action}.render().unwrap(), None, None).unwrap();
        }
        client.update(&CreateInsertPolicy{table_name, table_cols: table_cols.as_slice()}.render().unwrap(), None,None).unwrap();
        client.update(&CreateSelectPolicy{table_name, table_cols: table_cols.as_slice()}.render().unwrap(), None,None).unwrap();
        client.update(&CreateUpdatePolicy{table_name, table_cols: table_cols.as_slice()}.render().unwrap(), None,None).unwrap();
        client.update(&CreateDeletePolicy{table_name, table_cols: table_cols.as_slice()}.render().unwrap(), None,None).unwrap();
        // Anything else to do? Nope.        
    });
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
fn oso_is_allowed(subject: &str, object: AnyElement, action: &str) -> bool {
    // PgHeapTuple lets us actually access fields from 'object'
    let ht = unsafe {
        PgHeapTuple::from_datum(object.datum(), object.datum().is_null())
    }.unwrap();
    
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
        }).unwrap().unwrap();

        let mut cb = ExtClassBuilder::new(object.oid().as_u32().into(), class_name);
        for (_, attinfo) in ht.attributes() {
            let name: String = attinfo.name().to_string();
            let name2 = name.clone();
            cb = cb.add_attribute_getter(&name, move |instance: &HashMap<String, PolarValue>| {
                let get = instance.get(&name2);
                ToPolarWrapPolarValue(get.unwrap().clone())
            });
        }
        let class = cb.build();

        oso.register_class(class.clone()).unwrap();
        hm.insert(object.oid(), class);
        // types have to be registered before policies, so reload our policy if we had to load a new class
        // https://docs.osohq.com/any/project/changelogs/2020-08-11.html
        oso.clear_rules().unwrap();
        oso.load_str(POLICY).unwrap();
    }

    // Collect into values we can supply to Polar later
    let hm_values: HashMap<String, PolarValue> = ht.attributes().map(|(attno, attinfo)| {
        let k = attinfo.name().to_string();
        let v: PolarValue = match attinfo.type_oid() {
            // TODO handle more types
            PgOid::BuiltIn(PgBuiltInOids::TEXTOID) => {
                let st = ht.get_by_index::<String>(attno);
                // What is a null PolarValue? Is there one? I can't find it
                let st = st.unwrap().unwrap_or("".to_string());
                st.to_polar()
            },
            PgOid::BuiltIn(PgBuiltInOids::TIMESTAMPTZOID) => {
                let ts = ht.get_by_index::<TimestampWithTimeZone>(attno);
                let ts = ts.unwrap().map(|tswz| {format!("{:?}", tswz)});
                ts.to_polar()
            },
            x => panic!("unsupported type_oid {:?}", x)
        };
        (k, v)
    }).collect();
    let instance = Instance::new_ext(hm_values, object.oid().as_u32().into(), "foo"); // Debug name isn't important.
    oso.is_allowed(subject, action, ToPolarWrapPolarValue(PolarValue::Instance(instance))).unwrap()
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgx::prelude::*;

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
