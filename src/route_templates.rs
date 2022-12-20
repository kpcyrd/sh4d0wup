use crate::artifacts::HashedArtifact;
use crate::errors::*;
use handlebars::{
    Context, Handlebars, Helper, HelperDef, HelperResult, Output, PathAndJson, RenderContext,
    RenderError,
};
use serde_json::Value;

#[derive(Debug)]
enum HashType {
    Sha256,
    Sha1,
    Md5,
}

struct HashHelper<'a> {
    artifact: &'a HashedArtifact,
    hash: HashType,
}

impl<'a> HashHelper<'a> {
    fn new(artifact: &HashedArtifact, hash: HashType) -> HashHelper {
        HashHelper { artifact, hash }
    }
}

impl<'a> HelperDef for HashHelper<'a> {
    fn call<'_reg: '_rc, '_rc>(
        &self,
        _: &Helper,
        _: &'_reg Handlebars,
        _: &Context,
        _: &mut RenderContext,
        out: &mut dyn Output,
    ) -> Result<(), RenderError> {
        let hash = match self.hash {
            HashType::Sha256 => self.artifact.sha256(),
            HashType::Sha1 => self.artifact.sha1(),
            HashType::Md5 => self.artifact.md5(),
        };
        out.write(&hash).map_err(RenderError::from)
    }
}

pub fn render(path_template: &str, artifact: &HashedArtifact) -> Result<String> {
    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars
        .register_template_string("t", path_template)
        .with_context(|| anyhow!("Failed to parse path_template: {:?}", path_template))?;
    handlebars.register_helper("slice-until", Box::new(slice_until));
    handlebars.register_helper("slice-after", Box::new(slice_after));

    handlebars.register_helper(
        "sha256",
        Box::new(HashHelper::new(artifact, HashType::Sha256)),
    );
    handlebars.register_helper("sha1", Box::new(HashHelper::new(artifact, HashType::Sha1)));
    handlebars.register_helper("md5", Box::new(HashHelper::new(artifact, HashType::Md5)));

    let rendered = handlebars
        .render("t", &())
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
