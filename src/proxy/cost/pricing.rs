/// USD price per 1M tokens for a model.
///
/// **Not authoritative.** This table exists to estimate spend for budget
/// enforcement (a denial-of-wallet safety net), not to produce a billing-
/// accurate ledger. Prices come from the `llm-prices` crate (dated rows read
/// from each provider's pricing page), so a model is priced at its own rate
/// rather than at a family-wide guess. Model ids the table does not list fall
/// back to the family heuristics below and then to `default_pricing()`, which
/// deliberately errs toward overestimating rather than undercounting, since
/// undercounting would make a budget cap silently ineffective.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelPricing {
    pub input_per_million: f64,
    pub output_per_million: f64,
}

pub fn lookup(provider_slug: &str, model: &str) -> ModelPricing {
    if let Some(p) = listed_pricing(provider_slug, model) {
        return p;
    }
    let model = model.to_ascii_lowercase();
    match provider_slug {
        "anthropic" => anthropic_pricing(&model),
        "openai" => openai_pricing(&model),
        _ => default_pricing(),
    }
}

/// The model's own listed price, when `llm-prices` knows the provider slug
/// (`anthropic`, `openai`, `google`, `deepseek`, `mistral`, `groq`, ...) and
/// lists both an input and an output price for the model id. Dated snapshot
/// ids (`claude-haiku-4-5-20251001`) resolve to their base row.
fn listed_pricing(provider_slug: &str, model: &str) -> Option<ModelPricing> {
    let row = llm_prices::lookup_provider(provider_slug, model)?;
    Some(ModelPricing {
        input_per_million: row.input?,
        output_per_million: row.output?,
    })
}

/// Family fallback for Anthropic ids the price table does not list yet.
/// Each tier uses the highest price that family has been sold at, so an
/// unlisted model is never priced below what it could cost.
fn anthropic_pricing(model: &str) -> ModelPricing {
    if model.contains("opus") {
        ModelPricing {
            input_per_million: 15.0,
            output_per_million: 75.0,
        }
    } else if model.contains("haiku") {
        ModelPricing {
            input_per_million: 1.0,
            output_per_million: 5.0,
        }
    } else if model.contains("sonnet") {
        ModelPricing {
            input_per_million: 3.0,
            output_per_million: 15.0,
        }
    } else {
        default_pricing()
    }
}

/// Family fallback for OpenAI ids the price table does not list yet.
fn openai_pricing(model: &str) -> ModelPricing {
    if model.contains("gpt-4o-mini") {
        ModelPricing {
            input_per_million: 0.15,
            output_per_million: 0.60,
        }
    } else if model.contains("gpt-4o") {
        ModelPricing {
            input_per_million: 2.50,
            output_per_million: 10.0,
        }
    } else if model.contains("gpt-4.1-mini") {
        ModelPricing {
            input_per_million: 0.40,
            output_per_million: 1.60,
        }
    } else if model.contains("gpt-4.1") {
        ModelPricing {
            input_per_million: 2.0,
            output_per_million: 8.0,
        }
    } else if model.starts_with("o1") || model.starts_with("o3") || model.starts_with("o4") {
        ModelPricing {
            input_per_million: 15.0,
            output_per_million: 60.0,
        }
    } else {
        default_pricing()
    }
}

/// Conservative fallback for unknown providers/models.
fn default_pricing() -> ModelPricing {
    ModelPricing {
        input_per_million: 5.0,
        output_per_million: 15.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_opus_pricing() {
        // Opus 4.5 and later list at 5/25, not the 15/75 of Opus 4.1.
        let p = lookup("anthropic", "claude-opus-4-8");
        assert_eq!(p.input_per_million, 5.0);
        assert_eq!(p.output_per_million, 25.0);
        let old = lookup("anthropic", "claude-opus-4-1-20250805");
        assert_eq!(old.input_per_million, 15.0);
        assert_eq!(old.output_per_million, 75.0);
    }

    #[test]
    fn test_anthropic_sonnet_pricing() {
        let p = lookup("anthropic", "claude-sonnet-4-6");
        assert_eq!(p.input_per_million, 3.0);
        assert_eq!(p.output_per_million, 15.0);
    }

    #[test]
    fn test_anthropic_haiku_pricing() {
        // Haiku 4.5 is 1/5. The old family-wide 0.80/4.0 undercounted it by 20%.
        let p = lookup("anthropic", "claude-haiku-4-5");
        assert_eq!(p.input_per_million, 1.0);
        assert_eq!(p.output_per_million, 5.0);
        let dated = lookup("anthropic", "claude-haiku-4-5-20251001");
        assert_eq!(p, dated);
    }

    #[test]
    fn test_openai_reasoning_models_priced_per_model() {
        let o3 = lookup("openai", "o3");
        assert_eq!((o3.input_per_million, o3.output_per_million), (2.0, 8.0));
        let o4_mini = lookup("openai", "o4-mini");
        assert_eq!(
            (o4_mini.input_per_million, o4_mini.output_per_million),
            (1.1, 4.4)
        );
        // o3-pro costs more than the old 15/60 o-series guess.
        let o3_pro = lookup("openai", "o3-pro");
        assert_eq!(
            (o3_pro.input_per_million, o3_pro.output_per_million),
            (20.0, 80.0)
        );
    }

    #[test]
    fn test_openai_gpt5_family_is_not_underpriced_by_default() {
        // gpt-5.5-pro is 30/180: the 5/15 default undercounted it 6x on
        // input and 12x on output, so a budget cap let ~12x the spend through.
        let pro = lookup("openai", "gpt-5.5-pro");
        assert_eq!(
            (pro.input_per_million, pro.output_per_million),
            (30.0, 180.0)
        );
        let gpt5 = lookup("openai", "gpt-5");
        assert_eq!(
            (gpt5.input_per_million, gpt5.output_per_million),
            (1.25, 10.0)
        );
    }

    #[test]
    fn test_other_provider_slugs_use_listed_prices() {
        let p = lookup("google", "gemini-2.5-pro");
        assert_eq!((p.input_per_million, p.output_per_million), (1.25, 10.0));
    }

    #[test]
    fn test_unlisted_haiku_falls_back_to_family_price() {
        let p = lookup("anthropic", "claude-haiku-9-not-yet-listed");
        assert_eq!((p.input_per_million, p.output_per_million), (1.0, 5.0));
    }

    #[test]
    fn test_openai_gpt4o_vs_mini_are_different() {
        let full = lookup("openai", "gpt-4o");
        let mini = lookup("openai", "gpt-4o-mini");
        assert!(full.input_per_million > mini.input_per_million);
    }

    #[test]
    fn test_case_insensitive_model_match() {
        let a = lookup("anthropic", "Claude-Opus-4-8");
        let b = lookup("anthropic", "claude-opus-4-8");
        assert_eq!(a, b);
    }

    #[test]
    fn test_unknown_model_uses_conservative_default() {
        let known = lookup("anthropic", "claude-haiku-4-5");
        let unknown = lookup("anthropic", "some-brand-new-model-not-in-table");
        assert!(
            unknown.input_per_million >= known.input_per_million,
            "unknown models should not be UNDER-priced relative to the cheapest known tier"
        );
    }

    #[test]
    fn test_unknown_provider_uses_default() {
        let p = lookup("some-custom-provider", "whatever-model");
        assert_eq!(p, default_pricing());
    }
}
