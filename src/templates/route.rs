use crate::artifacts::HashedArtifact;
use crate::errors::*;
use crate::templates;
use handlebars::{Context, Handlebars, Helper, HelperDef, Output, RenderContext, RenderError};

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

pub fn render(
    path_template: &str,
    artifact: &HashedArtifact,
    metadata: Option<&templates::ArtifactMetadata>,
) -> Result<String> {
    let mut handlebars = templates::create_engine(path_template)?;

    handlebars.register_helper(
        "sha256",
        Box::new(HashHelper::new(artifact, HashType::Sha256)),
    );
    handlebars.register_helper("sha1", Box::new(HashHelper::new(artifact, HashType::Sha1)));
    handlebars.register_helper("md5", Box::new(HashHelper::new(artifact, HashType::Md5)));

    let values = metadata.map(|m| m.to_values()).unwrap_or_default();

    let rendered = handlebars
        .render("t", &values)
        .context("Failed to render path_template")?;
    debug!("Rendered path for route: {:?}", rendered);
    Ok(rendered)
}
