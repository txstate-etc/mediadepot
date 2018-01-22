use std::collections::HashMap;

use serde_json::value::{Value, to_value};
use tera::Error;
use chrono::NaiveDate;
use time::Duration;

pub fn dateadd(value: Value, args: HashMap<String, Value>) -> Result<Value, Error> {
    let days = match args.get("days") {
        Some(d) => try_get_value!("dateadd", "days", i64, d),
        None => 0,
    };
    let s = try_get_value!("dateadd", "value", String, value);

    match NaiveDate::parse_from_str(&s[0..10], "%Y-%m-%d") {
        Ok(val) => {

            let purge_date = val.checked_add_signed(Duration::days(days)).unwrap();
            Ok(to_value(purge_date.format("%Y-%m-%d").to_string())?)
        },
        Err(_) => bail!("Error in dateadd with parsing `{:?}` as YYYY-MM-DD date", &s[0..9]),
    }

}
