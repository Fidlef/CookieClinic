# Security notes

- Analysis occurs in the browser tab and makes no network request.
- Never paste a live session identifier. Use a fake value while preserving only
  the attributes under review.
- Browser cookie behavior changes over time. Confirm production decisions
  against current browser and framework documentation.
- A correct header cannot compensate for an insecure application or session
  lifecycle.
