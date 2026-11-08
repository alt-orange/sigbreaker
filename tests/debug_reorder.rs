//! Opt-in local bisect harness; paths come from SB_INPUT and SB_OUTPUT.
#![allow(dead_code)]

use rand::rngs::StdRng;
use rand::SeedableRng;
use sigbraker::analysis::Analysis;
use sigbraker::pe::{PeFile, PeLayout};

/// Reorder only the first `limit` functions (bisect helper).
fn reorder_upto(
    analysis: &Analysis,
    layout: &PeLayout,
    data: &mut [u8],
    rng: &mut StdRng,
    limit: usize,
) {
    use rand::Rng;
    use sigbraker::dependencies;
    use sigbraker::transforms::relocate_ip_relative;

    type RecordedOrder = (usize, usize, Vec<usize>, Vec<Vec<usize>>);
    let mut orders: Vec<RecordedOrder> = Vec::new();

    for (f_idx, func) in analysis.functions.iter().enumerate() {
        // Bisect mode: reorder ONLY one function's blocks (<= SB_BLOCK).
        let bisect = (
            std::env::var("SB_FUNC")
                .ok()
                .and_then(|v| v.parse::<usize>().ok()),
            std::env::var("SB_BLOCK")
                .ok()
                .and_then(|v| v.parse::<usize>().ok()),
        );
        let bisect_active = bisect.0.is_some() && bisect.1.is_some();
        if !bisect_active && f_idx >= limit {
            break;
        }
        if bisect_active && f_idx != bisect.0.unwrap() {
            continue;
        }
        for (block_idx, block) in func.blocks.iter().enumerate() {
            if block_idx == 0 {
                continue;
            }
            if bisect_active && block_idx > bisect.1.unwrap() {
                continue;
            }
            if rng.gen::<f64>() >= 1.0 {
                continue;
            }
            let n = block.instrs.len();
            let body_len = if block.instrs[n - 1].ends_block() {
                n - 1
            } else {
                n
            };
            if body_len < 2 {
                continue;
            }
            let body = &block.instrs[..body_len];
            if body.iter().any(|i| i.pinned) {
                continue;
            }
            let dag = dependencies::build(body);
            let order = dependencies::random_topo_order(&dag.deps, rng);
            if order.iter().enumerate().all(|(k, &v)| k == v) {
                continue;
            }
            let base = body[0].off;
            let base_rva = body[0].rva;
            let total: usize = body.iter().map(|i| i.len).sum();
            let mut buf = Vec::with_capacity(total);
            let mut cursor_rva = base_rva;
            let mut failed = false;
            for &idx in &order {
                let src = &body[idx];
                let bytes = &data[src.off..src.off + src.len];
                if src.iced.is_ip_rel_memory_operand() && src.rva != cursor_rva {
                    match relocate_ip_relative(&src.iced, layout.va(cursor_rva), src.len) {
                        Some(fixed) => buf.extend_from_slice(&fixed),
                        None => {
                            failed = true;
                            break;
                        }
                    }
                } else {
                    buf.extend_from_slice(bytes);
                }
                cursor_rva += src.len as u32;
            }
            if failed {
                continue;
            }
            data[base..base + total].copy_from_slice(&buf);
            orders.push((f_idx, block_idx, order.clone(), dag.deps.clone()));
        }
    }

    // Validate every permutation against its ORIGINAL DAG.
    let mut violations = 0;
    for (f_idx, b_idx, order, deps) in &orders {
        let mut pos = vec![0usize; order.len()];
        for (p, &v) in order.iter().enumerate() {
            pos[v] = p;
        }
        for (i, d) in deps.iter().enumerate() {
            for &dep in d {
                if pos[dep] >= pos[i] {
                    violations += 1;
                    if violations <= 20 {
                        println!(
                            "func #{f_idx} block {b_idx}: instr {i} ({}) at {} depends on instr {dep} ({}) at {}",
                            analysis.functions[*f_idx].blocks[*b_idx].instrs[i].iced,
                            pos[i],
                            analysis.functions[*f_idx].blocks[*b_idx].instrs[dep].iced,
                            pos[dep]
                        );
                    }
                }
            }
        }
    }
    println!("orders: {} violations: {violations}", orders.len());
}

#[test]
#[ignore = "manual bisect harness; requires SB_INPUT and SB_OUTPUT"]
fn debug_reorder_bisect() {
    let limit: usize = std::env::var("SB_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(912);
    let raw = std::fs::read(std::env::var("SB_INPUT").expect("SB_INPUT path required")).unwrap();
    let mut pe = PeFile::parse(raw).unwrap();
    let layout = pe.layout().clone();
    let analysis = Analysis::run(&layout, &pe.data).unwrap();

    let mut rng = StdRng::seed_from_u64(99);
    reorder_upto(&analysis, &layout, &mut pe.data, &mut rng, limit);

    std::fs::write(
        std::env::var("SB_OUTPUT").expect("SB_OUTPUT path required"),
        &pe.data,
    )
    .unwrap();
    println!("limit = {limit}");
}
