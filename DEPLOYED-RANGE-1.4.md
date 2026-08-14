# Sentinel Blue 1.4 deployed-range report

Deployment date: 2026-08-13

## Deployment

The frozen `sentinel-blue-1.4.0.pyz` package was deployed into its isolated,
disposable end-to-end range at the implemented ceiling of 5,000 scenarios.
The campaign exercised enrollment, baseline approval, protected identities,
detection, operator decisions, action queuing/completion, feedback, protocol
validation, and controller persistence. It did not contact or modify external
hosts.

## Result

| Measurement | Result |
|---|---:|
| Scenarios | 5,000 |
| True positives | 3,945 |
| False positives | 0 |
| True negatives | 1,055 |
| False negatives | 0 |
| Synthetic precision | 100% |
| Synthetic recall | 100% |
| Actions queued | 4,218 |
| Actions completed | 4,218 |
| Feedback records | 4,218 |
| Hostile protocol inputs | 5,000/5,000 rejected |
| Invalid inputs accepted | 0 |
| Valid protocol samples | 100/100 accepted |
| Containment | Dry-run |

Every encoded scenario completed with its expected outcome. These results are
regression evidence for the disposable range, not a CCDC uptime prediction.

## Boundary

This deployment was the self-contained local range included with Sentinel Blue.
A live multi-VM deployment still requires authorized Windows/Linux guests,
network reachability and credentials, scorer definitions, protected identities,
and the competition portal or practice-range access method.
