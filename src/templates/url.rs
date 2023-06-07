use crate::errors::*;
use crate::templates;

pub fn render(url_template: &str, artifact: &templates::ArtifactMetadata) -> Result<String> {
    let handlebars = templates::create_engine(url_template)?;

    let rendered = handlebars
        .render("t", &artifact.to_values())
        .context("Failed to render url_template")?;
    debug!("Rendered url: {:?}", rendered);
    Ok(rendered)
}
