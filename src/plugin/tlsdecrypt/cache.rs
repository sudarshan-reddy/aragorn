use std::io::Seek;
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    num::NonZeroUsize,
    sync::Arc,
};

use anyhow::{Error, Result};
use lru::LruCache;
use nom::{
    bytes::complete::{tag, take_while1},
    character::complete::{line_ending, space1},
    IResult,
};
use tokio::sync::Mutex;

pub struct CachedTLSSessionKeys<R: Read> {
    // Key: client_random
    // Value: session_key
    hot_cache: Arc<Mutex<LruCache<String, String>>>,

    reader: BufReader<R>,
}

pub struct SSLSessionKey {
    pub client_random: String,
    pub master_key: String,
}

impl<R: Read + Seek> CachedTLSSessionKeys<R> {
    pub fn new(size: NonZeroUsize, reader: R) -> Result<Self> {
        Ok(Self {
            hot_cache: Arc::new(Mutex::new(LruCache::new(size))),
            reader: BufReader::new(reader),
        })
    }

    pub fn new_with_file(size: NonZeroUsize, file: &str) -> Result<CachedTLSSessionKeys<File>> {
        let file = File::open(file)?;
        let cache: CachedTLSSessionKeys<File> = CachedTLSSessionKeys::new(size, file)?;
        Ok(cache)
    }

    // An alternative way to do this is have an file watcher using the notify library and update the cache.
    // The only downside of that approach is the poll_interval. We might have the cache updated a
    // bit too late. This current method of loading the file into memory is a bit more intensive
    // but robust. Perhaps a good improvement is to have both approaches in the future:
    //
    // i.e. Use notify to feed into the LRU Cache and have a fallback to load the file into memory.
    pub async fn get(&mut self, client_random: &str) -> Result<Option<String>> {
        {
            let mut hot_cache = self.hot_cache.lock().await;
            if let Some(master_key) = hot_cache.get(client_random) {
                return Ok(Some(master_key.clone()));
            }
        }

        // reset reader to the beginning of the file
        // Reset reader to the beginning of the file by seeking to start.
        self.reader.get_mut().seek(std::io::SeekFrom::Start(0))?;
        // Make sure to reset the BufReader's buffer state after seeking
        self.reader.consume(self.reader.buffer().len());
        loop {
            let ssl_pair = self.parse_line()?;
            match ssl_pair {
                Some(ssl_pair) => {
                    let mut hot_cache = self.hot_cache.lock().await;
                    hot_cache.put(ssl_pair.client_random.clone(), ssl_pair.master_key.clone());
                    if client_random == ssl_pair.client_random {
                        return Ok(Some(ssl_pair.master_key));
                    }
                }
                None => {
                    break;
                }
            }
        }

        Ok(None)
    }

    fn parse_line(&mut self) -> Result<Option<SSLSessionKey>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => {
                if let Ok((_, (client_random, master_key))) = parse_client_random(&line) {
                    Ok(Some(SSLSessionKey {
                        client_random: client_random.to_string(),
                        master_key: master_key.to_string(),
                    }))
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(Error::new(e)),
        }
    }
}

fn parse_client_random(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, _) = tag("CLIENT_RANDOM")(input)?;
    let (input, _) = space1(input)?;
    let (input, random1) = take_while1(|c: char| c.is_ascii_hexdigit())(input)?;
    let (input, _) = space1(input)?;
    let (input, random2) = take_while1(|c: char| c.is_ascii_hexdigit())(input)?;
    let (input, _) = line_ending(input)?;
    Ok((input, (random1, random2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFile {
        original_data: Vec<u8>,
        data: Vec<u8>,
    }

    impl Read for MockFile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let len = std::cmp::min(buf.len(), self.data.len());
            buf[..len].copy_from_slice(&self.data[..len]);
            self.data = self.data[len..].to_vec();
            Ok(len)
        }
    }

    impl Seek for MockFile {
        fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
            self.data = self.original_data.clone();
            Ok(0)
        }
    }

    impl MockFile {
        fn new_sample() -> Self {
            // Create a mock file that looks like this:
            // ```
            // CLIENT_RANDOM E22FC09BC9DD273C64D73F8BEC53080DBC18478B67602F609AF56224C8B330D7 BFFC62DC2EB285F0D08A3689F43A6C776EB73E04ED673FBF993793B759C3C39BDD553C973DC7294982F0EC966DF70016
            //CLIENT_RANDOM D229A4390A506CB8EDC05556423152717AB98D236EB17E66AFC5EC2E833CCDB3 B9C14604B207433510EB20EC70FCB5FB1C08B7B94BAEBC45AD330840E6B8BB1D98D13861C0ECCEF019FC39C8D0BBD24F
            //CLIENT_RANDOM E15F76A50421F93726584BC785DC6B5885BEDF33E45E73C8D60246E0F975257F 672D31501A0BE8C8D7469F22EA424E41B3F1500214ED7AF003F5FC433CB9271BFE21B722C7F90B6B0E935B290D42072D
            //```
            let data = b"CLIENT_RANDOM E22FC09BC9DD273C64D73F8BEC53080DBC18478B67602F609AF56224C8B330D7 BFFC62DC2EB285F0D08A3689F43A6C776EB73E04ED673FBF993793B759C3C39BDD553C973DC7294982F0EC966DF70016\nCLIENT_RANDOM D229A4390A506CB8EDC05556423152717AB98D236EB17E66AFC5EC2E833CCDB3 B9C14604B207433510EB20EC70FCB5FB1C08B7B94BAEBC45AD330840E6B8BB1D98D13861C0ECCEF019FC39C8D0BBD24F\nCLIENT_RANDOM E15F76A50421F93726584BC785DC6B5885BEDF33E45E73C8D60246E0F975257F 672D31501A0BE8C8D7469F22EA424E41B3F1500214ED7AF003F5FC433CB9271BFE21B722C7F90B6B0E935B290D42072D\n";
            Self {
                data: data.to_vec(),
                original_data: data.to_vec(),
            }
        }
    }

    #[test]
    fn test_parse_line() {
        let mock_file = MockFile::new_sample();
        let mut cache =
            CachedTLSSessionKeys::new(NonZeroUsize::new(10).unwrap(), mock_file).unwrap();
        let session_key = cache.parse_line().unwrap().unwrap();
        assert_eq!(
            session_key.client_random,
            "E22FC09BC9DD273C64D73F8BEC53080DBC18478B67602F609AF56224C8B330D7"
        );
        assert_eq!(
            session_key.master_key,
            "BFFC62DC2EB285F0D08A3689F43A6C776EB73E04ED673FBF993793B759C3C39BDD553C973DC7294982F0EC966DF70016"
        );

        let session_key = cache.parse_line().unwrap().unwrap();
        assert_eq!(
            session_key.client_random,
            "D229A4390A506CB8EDC05556423152717AB98D236EB17E66AFC5EC2E833CCDB3"
        );
        assert_eq!(
            session_key.master_key,
            "B9C14604B207433510EB20EC70FCB5FB1C08B7B94BAEBC45AD330840E6B8BB1D98D13861C0ECCEF019FC39C8D0BBD24F"
        );

        let session_key = cache.parse_line().unwrap().unwrap();
        assert_eq!(
            session_key.client_random,
            "E15F76A50421F93726584BC785DC6B5885BEDF33E45E73C8D60246E0F975257F"
        );
        assert_eq!(
            session_key.master_key,
            "672D31501A0BE8C8D7469F22EA424E41B3F1500214ED7AF003F5FC433CB9271BFE21B722C7F90B6B0E935B290D42072D"
        );

        let session_key = cache.parse_line().unwrap();
        assert!(session_key.is_none());
    }

    #[tokio::test]
    async fn test_get() {
        let mock_file = MockFile::new_sample();
        let mut cache =
            CachedTLSSessionKeys::new(NonZeroUsize::new(10).unwrap(), mock_file).unwrap();
        let master_key = cache
            .get("E15F76A50421F93726584BC785DC6B5885BEDF33E45E73C8D60246E0F975257F")
            .await
            .unwrap();
        assert_eq!(
            master_key,
            Some("672D31501A0BE8C8D7469F22EA424E41B3F1500214ED7AF003F5FC433CB9271BFE21B722C7F90B6B0E935B290D42072D".to_string())
        );

        let master_key = cache
            .get("D229A4390A506CB8EDC05556423152717AB98D236EB17E66AFC5EC2E833CCDB3")
            .await
            .unwrap();
        assert_eq!(
            master_key,
            Some("B9C14604B207433510EB20EC70FCB5FB1C08B7B94BAEBC45AD330840E6B8BB1D98D13861C0ECCEF019FC39C8D0BBD24F".to_string())
        );

        {
            let mut locked_cache = cache.hot_cache.lock().await;
            let master_key = locked_cache
                .get("E22FC09BC9DD273C64D73F8BEC53080DBC18478B67602F609AF56224C8B330D7");

            assert_eq!(master_key,
                   Some(&"BFFC62DC2EB285F0D08A3689F43A6C776EB73E04ED673FBF993793B759C3C39BDD553C973DC7294982F0EC966DF70016".to_string()));

            // delete the key from the cache and check if it is fetched from the file
            locked_cache.pop("E22FC09BC9DD273C64D73F8BEC53080DBC18478B67602F609AF56224C8B330D7");
        }

        let master_key = cache
            .get("E22FC09BC9DD273C64D73F8BEC53080DBC18478B67602F609AF56224C8B330D7")
            .await
            .unwrap();

        assert_eq!(
            master_key,
            Some("BFFC62DC2EB285F0D08A3689F43A6C776EB73E04ED673FBF993793B759C3C39BDD553C973DC7294982F0EC966DF70016".to_string())
        );
    }
}
