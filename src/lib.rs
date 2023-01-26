use std::{sync::Mutex, collections::HashMap};
use pgx::{prelude::*, AnyElement, IntoDatum, FromDatum, pg_sys::Oid};
use oso::{Oso, PolarValue, ExtClassBuilder, Class, ToPolar, Instance};
use lazy_static::lazy_static;

pgx::pg_module_magic!();

static POLICY: &'static str = r#"allow(subject, "read", object: comments) if object.author = subject;"#;

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
fn oso_configure_rls(table_name: &str) {
    // Spi::connect(|client| {
    //     client.update(format!("alter table {} enable row level security", table_name), None, None)
    //     .
    // }).unwrap();
}

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
