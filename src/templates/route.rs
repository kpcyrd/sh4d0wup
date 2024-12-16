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

impl HashHelper<'_> {
    fn new(artifact: &HashedArtifact, hash: HashType) -> HashHelper {
        HashHelper { artifact, hash }
    }
}

impl HelperDef for HashHelper<'_> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_url() -> Result<()> {
        let template = "/hax.git/objects/{{slice-until (sha1) 2}}/{{slice-after (sha1) 2}}";
        let output = render(template, &HashedArtifact::new(b"ohai".to_vec()), None)?;
        assert_eq!(
            output,
            "/hax.git/objects/dc/a51952447d80bd35bf631bc21f06648798b7e0"
        );
        Ok(())
    }
}
