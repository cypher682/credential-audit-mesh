use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub service_name: String,
    pub port: u16,
    pub log_level: String,
    pub database_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            service_name: crate::SERVICE_NAME.to_string(),
            port: 8083,
            log_level: "info".to_string(),
            database_url: None,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, String> {
        Self::from_lookup(|key| env::var(key).ok())
    }

    pub fn from_lookup<F>(get: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut cfg = Self::default();

        if let Some(v) = get("SERVICE_NAME").filter(|v| !v.is_empty()) {
            cfg.service_name = v;
        }
        if let Some(v) = get("LOG_LEVEL").filter(|v| !v.is_empty()) {
            cfg.log_level = v;
        }
        if let Some(v) = get("PORT").filter(|v| !v.is_empty()) {
            cfg.port = v
                .parse::<u16>()
                .map_err(|_| format!("invalid PORT {v:?}"))?;
            if cfg.port == 0 {
                return Err(format!("invalid PORT {v:?}"));
            }
        }
        if let Some(v) = get("DATABASE_URL").filter(|v| !v.is_empty()) {
            cfg.database_url = Some(v);
        }

        Ok(cfg)
    }

    pub fn addr(&self) -> String {
        format!("0.0.0.0:{}", self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        let cfg = Config::from_lookup(|_| None).expect("config");
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.port, 8083);
    }

    #[test]
    fn reads_overrides() {
        let cfg = Config::from_lookup(|key| match key {
            "SERVICE_NAME" => Some("mesh".into()),
            "PORT" => Some("9090".into()),
            "DATABASE_URL" => Some("postgres://localhost/mesh".into()),
            _ => None,
        })
        .expect("config");
        assert_eq!(cfg.service_name, "mesh");
        assert_eq!(cfg.port, 9090);
        assert_eq!(cfg.database_url.as_deref(), Some("postgres://localhost/mesh"));
    }

    #[test]
    fn rejects_bad_port() {
        assert!(Config::from_lookup(|key| (key == "PORT").then(|| "nope".into())).is_err());
        assert!(Config::from_lookup(|key| (key == "PORT").then(|| "0".into())).is_err());
    }
}
