use std::collections::HashMap;

use anyhow::Context;

use crate::{pcre, utils::qx};

pub fn is_service_active(service: &str) -> anyhow::Result<bool> {
    Ok(get_service_info(service)?
        .get("ActiveState")
        .map(|field| field == "active")
        .unwrap_or(false))
}

pub fn get_service_info(service: &str) -> anyhow::Result<HashMap<String, String>> {
    let service_info = qx(&format!("systemctl show --no-pager {service}"))
        .context("Could not show service info")?
        .1;

    Ok(pcre!(
        &service_info =~ m{r"([^=]+)=([^\n]+)"}gxms
    )
    .into_iter()
    .map(|c| c.extract::<2>().1)
    .map(|[k, v]| (k.trim().to_string(), v.trim().to_string()))
    .collect::<HashMap<_, _>>())
}
