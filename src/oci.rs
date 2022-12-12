#[cfg(test)]
pub mod tests {
    // use super::*;

    #[test]
    fn test_parse_manifest() {
        let _data = br#"{
   "schemaVersion": 2,
   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
   "config": {
      "mediaType": "application/vnd.docker.container.image.v1+json",
      "size": 1923,
      "digest": "sha256:19afcbba349ae5e68e7cc33a6baca28684303859a1adc960dc23ea62ad94acae"
   },
   "layers": [
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 2806272,
         "digest": "sha256:ca7dd9ec2225f2385955c43b2379305acd51543c28cf1d4e94522b3d94cce3ce"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 77815134,
         "digest": "sha256:71b2a6c9afcbd6bd27c57995c37671cafdafaedbb8128e48d2ceead32af97704"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 5576776,
         "digest": "sha256:52563251f879dca313b27ba5b902c437600e62196998398de3e19221803e416e"
      }
   ]
}"#;
    }
}
