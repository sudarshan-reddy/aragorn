use super::{PostProcessor, ProcessedResult};
use anyhow::Result;
use async_trait::async_trait;
use prometheus::{register_counter_vec, register_histogram_vec, CounterVec, HistogramVec};

pub struct PrometheusPostProcessor {
    requests: CounterVec,
    errors: CounterVec,
    latency: HistogramVec,
}

impl PrometheusPostProcessor {
    pub fn new() -> Self {
        let requests =
            register_counter_vec!("requests_total", "Number of requests", &["key"]).unwrap();

        let errors = register_counter_vec!("errors_total", "Number of errors", &["key"]).unwrap();

        let latency =
            register_histogram_vec!("latency_seconds", "Request latency in seconds", &["key"])
                .unwrap();

        PrometheusPostProcessor {
            requests,
            errors,
            latency,
        }
    }
}

#[async_trait]
impl PostProcessor for PrometheusPostProcessor {
    async fn post_process(&self, res: ProcessedResult) -> Result<()> {
        match res {
            ProcessedResult::Prometheus(res) => {
                let label = res.label;
                let latency = res.latency;

                self.requests.with_label_values(&[&label]).inc();
                self.latency
                    .with_label_values(&[&label])
                    .observe(latency as f64);
                if res.is_error {
                    self.errors.with_label_values(&[&label]).inc();
                }
            }
        }
        Ok(())
    }
}
