use anyhow::anyhow;
use serde_json::{json, Value};

static mut NONCE: u32 = 0;

/* generate a pseudo unique out point:
{
    "tx_hash": "0x0000000000000000000000000000000000000000000000000000000000000005",
    "index": "0x0"
}
*/
fn gen_outpoint() -> Value {
    let tx_hash = unsafe {
        let r = format!(
            "0x000000000000000000000000000000000000000000000000000000000000{:04X}",
            NONCE
        );
        NONCE += 1;
        r
    };
    json!({"tx_hash": tx_hash, "index": "0x0"})
}

/* generate a pseudo unique cell_dep:
{
    "out_point": {
        "tx_hash": "0x0000000000000000000000000000000000000000000000000000000000000005",
        "index": "0x0"
    },
    "dep_type": "code"
}
*/
fn gen_celldep() -> Value {
    json!({
        "out_point": gen_outpoint(),
        "dep_type": "code"
    })
}

/* generate a pseudo unique input */
fn gen_input() -> Value {
    json!({
        "previous_output": gen_outpoint(),
        "since": "0x0"
    })
}

fn fill_missing(root: &mut Value, child: &str, name: &str, value: Value) {
    let pointer = format!("/{}/{}", child, name);
    let node = root.pointer(&pointer);
    if node.is_none() {
        root[child][name] = value
    }
}

pub fn auto_complete(mock_tx: &str) -> Result<String, anyhow::Error> {
    let mut root: Value = serde_json::from_str(mock_tx)?;

    fill_missing(&mut root, "tx", "version", json!("0x0"));
    fill_missing(&mut root, "tx", "cell_deps", json!([]));
    fill_missing(&mut root, "tx", "header_deps", json!([]));
    fill_missing(&mut root, "tx", "inputs", json!([]));
    fill_missing(&mut root, "mock_info", "header_deps", json!([]));

    let mut index = 0;
    #[allow(while_true)]
    while true {
        let pointer = format!("/mock_info/cell_deps/{}", index);
        if let Some(cell_dep) = root.pointer_mut(&pointer) {
            if cell_dep.get("cell_dep").is_none() {
                cell_dep["cell_dep"] = gen_celldep();
            }
        } else {
            break;
        }
        index += 1;
    }

    let mut index = 0;
    #[allow(while_true)]
    while true {
        let pointer = format!("/mock_info/inputs/{}", index);
        if let Some(input) = root.pointer_mut(&pointer) {
            if input.get("input").is_none() {
                input["input"] = gen_input();
            }
        } else {
            break;
        }
        index += 1;
    }

    serde_json::to_string_pretty(&root).map_err(|e| anyhow!(e))
}
