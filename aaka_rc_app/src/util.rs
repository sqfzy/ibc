use blahaj::Share;
use tracing::{instrument, warn};

pub async fn distribute_shares(
    shares: &[Share],
    other_nodes: &[String],
) -> Result<(), reqwest::Error> {
    debug_assert_eq!(
        shares.len(),
        other_nodes.len(),
        "Number of shares must match number of nodes",
    );

    let client = reqwest::Client::new();
    for (peer_addr, share) in other_nodes.iter().zip(shares.iter()) {
        client
            .post(format!("http://{peer_addr}/set_share"))
            .json(&Vec::from(share))
            .send()
            .await?
            .error_for_status()
            .is_err()
            .then(|| {
                warn!("Failed to send share to peer {}", peer_addr);
            });
    }

    Ok(())
}

pub async fn collect_shares(
    self_share: Share,
    other_nodes: &[String],
) -> Result<Vec<Share>, reqwest::Error> {
    let mut shares = vec![self_share];

    let client = reqwest::Client::new();
    for peer_addr in other_nodes {
        let Ok(res) = client
            .get(format!("http://{peer_addr}/get_share"))
            .send()
            .await?
            .error_for_status()
        else {
            warn!("Failed to get share from peer {}", peer_addr);
            continue;
        };

        let share_bytes: Vec<u8> = res.json().await?;
        if let Ok(share) = Share::try_from(share_bytes.as_slice()) {
            shares.push(share);
        } else {
            warn!(
                "Failed to parse share from peer {}: {:?}",
                peer_addr, share_bytes
            );
        }
    }

    Ok(shares)
}
