use crate::artifacts::HashedArtifact;
use crate::errors::*;
use handlebars::{
    Context, Handlebars, Helper, HelperResult, Output, PathAndJson, RenderContext, RenderError,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub fn render(path_template: &str, artifact: &HashedArtifact) -> Result<String> {
    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars
        .register_template_string("t", path_template)
        .with_context(|| anyhow!("Failed to parse path_template: {:?}", path_template))?;
    handlebars.register_helper("slice-until", Box::new(slice_until));
    handlebars.register_helper("slice-after", Box::new(slice_after));

    let mut data = BTreeMap::new();
    data.insert("sha256".to_string(), artifact.sha256.clone());
    data.insert("sha1".to_string(), artifact.sha1.clone());

    let rendered = handlebars
        .render("t", &data)
        .context("Failed to render path_template")?;
    debug!("Rendered path for route: {:?}", rendered);
    Ok(rendered)
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
