/// Pre-computed RGB integers for D-18 colors: R*65536 + G*256 + B
const COLOR_CRITICAL: u32 = 16736324; // #ff4444
const COLOR_HIGH: u32 = 16746496; // #ff8800
const COLOR_MEDIUM: u32 = 16763904; // #ffcc00
const COLOR_LOW: u32 = 4505412; // #44bb44
const COLOR_HOST: u32 = 4491007; // #4488ff
const COLOR_CVE: u32 = 11157759; // #aa44ff
const COLOR_TECH: u32 = 4441292; // #44cccc

pub fn generate_graph_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "colorGroups": [
            { "query": "tag:#critical",   "color": { "a": 1, "rgb": COLOR_CRITICAL } },
            { "query": "tag:#high",       "color": { "a": 1, "rgb": COLOR_HIGH } },
            { "query": "tag:#medium",     "color": { "a": 1, "rgb": COLOR_MEDIUM } },
            { "query": "tag:#low",        "color": { "a": 1, "rgb": COLOR_LOW } },
            { "query": "tag:#host",       "color": { "a": 1, "rgb": COLOR_HOST } },
            { "query": "tag:#cve",        "color": { "a": 1, "rgb": COLOR_CVE } },
            { "query": "tag:#technology", "color": { "a": 1, "rgb": COLOR_TECH } }
        ],
        "showTags": true,
        "hideUnresolved": false,
        "showArrow": false,
        "nodeSizeMultiplier": 1,
        "lineSizeMultiplier": 1,
        "linkDistance": 250
    }))
    .expect("json serialization infallible")
}

pub fn generate_css_snippet() -> String {
    r#"/* PortReaper Severity Colors for Obsidian Graph View
 *
 * Installation:
 * 1. Copy this file to your vault's .obsidian/snippets/ directory
 * 2. In Obsidian, go to Settings -> Appearance -> CSS Snippets
 * 3. Enable "severity-colors"
 *
 * Note: Per-severity node coloring is handled by the generated
 * .obsidian/graph.json color groups (active automatically).
 * This CSS provides supplemental tag node styling.
 */

.theme-dark, .theme-light {
  --graph-node-tag: #aa44ff;
}
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_graph_json_contains_seven_color_groups() {
        let json = generate_graph_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let groups = parsed["colorGroups"].as_array().expect("colorGroups array");
        assert_eq!(groups.len(), 7, "should have exactly 7 color groups");
    }

    #[test]
    fn generate_graph_json_contains_critical_tag_query() {
        let json = generate_graph_json();
        assert!(json.contains("tag:#critical"), "should contain tag:#critical query");
    }

    #[test]
    fn generate_graph_json_critical_rgb_value_is_correct() {
        let json = generate_graph_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let groups = parsed["colorGroups"].as_array().expect("colorGroups array");
        let critical = groups
            .iter()
            .find(|g| g["query"].as_str() == Some("tag:#critical"))
            .expect("critical group not found");
        let rgb = critical["color"]["rgb"].as_u64().expect("rgb value");
        assert_eq!(rgb, 16736324, "critical RGB should be 16736324 (#ff4444)");
    }

    #[test]
    fn generate_css_snippet_contains_graph_node_tag_variable() {
        let css = generate_css_snippet();
        assert!(css.contains("--graph-node-tag"), "should contain --graph-node-tag CSS variable");
    }

    #[test]
    fn generate_css_snippet_contains_obsidian_snippets_instructions() {
        let css = generate_css_snippet();
        assert!(css.contains(".obsidian/snippets/"), "should contain installation path instructions");
    }
}
