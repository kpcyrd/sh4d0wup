pub mod route;
pub mod url;

use crate::errors::*;
use ::url::Url;
use handlebars::{
    Context, Handlebars, Helper, HelperResult, Output, PathAndJson, RenderContext, RenderError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub url: Url,
    pub filename: Option<String>,
    pub version: Option<String>,
    pub sha256: Option<String>,
}

impl ArtifactMetadata {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let artifact = serde_json::from_slice(bytes)?;
        Ok(artifact)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let buf = serde_json::to_vec(self)?;
        Ok(buf)
    }

    pub fn to_values(&self) -> HashMap<&'static str, String> {
        let mut values = HashMap::new();
        values.insert("url", self.url.to_string());

        if let Some(filename) = &self.filename {
            values.insert("filename", filename.to_string());
        }

        if let Some(version) = &self.version {
            values.insert("version", version.to_string());
        }

        values
    }
}

pub fn create_engine(template: &str) -> Result<Handlebars> {
    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars
        .register_template_string("t", template)
        .with_context(|| anyhow!("Failed to parse template: {:?}", template))?;
    handlebars.register_helper("slice-until", Box::new(slice_until));
    handlebars.register_helper("slice-after", Box::new(slice_after));

    Ok(handlebars)
}

fn param_to_str<'a>(
    param: Option<&'a PathAndJson>,
) -> std::result::Result<&'a String, RenderError> {
    if let Some(Value::String(value)) = param.map(|p| p.value()) {
        Ok(value)
    } else {
        Err(RenderError::new("Argument is missing or not a string"))
    }
}

fn param_to_u64(param: Option<&PathAndJson>) -> std::result::Result<u64, RenderError> {
    if let Some(Value::Number(num)) = param.map(|p| p.value()) {
        let value = num
            .as_u64()
            .ok_or_else(|| RenderError::new("Argument could not be converted to u64"))?;
        Ok(value)
    } else {
        Err(RenderError::new("Argument is missing or not a number"))
    }
}

fn param_to_usize(param: Option<&PathAndJson>) -> std::result::Result<usize, RenderError> {
    let value = param_to_u64(param)?
        .try_into()
        .map_err(|_| RenderError::new("Argument could not be converted to usize"))?;
    Ok(value)
}

pub fn slice_until(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _rc: &mut RenderContext,
    out: &mut dyn Output,
) -> HelperResult {
    let value = param_to_str(h.param(0))?;
    let idx = param_to_usize(h.param(1))?;

    out.write(&value[..idx])?;

    Ok(())
}

pub fn slice_after(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _rc: &mut RenderContext,
    out: &mut dyn Output,
) -> HelperResult {
    let value = param_to_str(h.param(0))?;
    let idx = param_to_usize(h.param(1))?;

    out.write(&value[idx..])?;

    Ok(())
}
