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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_url() -> Result<()> {
        let template =
            "{{ url }}files/{{slice-until sha256 2}}/{{slice-after sha256 2}}/{{ filename }}";
        let output = render(
            template,
            &templates::ArtifactMetadata {
                url: "https://example.com/".parse()?,
                filename: Some("hello.tgz".to_string()),
                version: Some("1.33.7-1".to_string()),
                sha256: Some(
                    "e84712238709398f6d349dc2250b0efca4b72d8c2bfb7b74339d30ba94056b14".to_string(),
                ),
            },
        )?;
        assert_eq!(
            output,
            "https://example.com/files/e8/4712238709398f6d349dc2250b0efca4b72d8c2bfb7b74339d30ba94056b14/hello.tgz"
        );
        Ok(())
    }
}
