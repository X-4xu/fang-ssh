# Fang: 14-Day Open-Source Launch Schedule

> [!IMPORTANT]
> **Cardinal Rules**:
> 1. **One Channel Per Day**: Never blast multiple communities at once. This avoids looking like spam and gives you time to meaningfully engage in each discussion.
> 2. **Rapid Response**: Monitor each thread actively for the first 8-12 hours after posting. Answer technical questions, acknowledge critiques with humility, and thank contributors.
> 3. **No Manipulation**: Never ask friends or co-workers to upvote, star, or comment artificially. Genuine technical merit is the only sustainable strategy.

---

## Daily Schedule

### Day 1: Hacker News (Show HN)
- **Action**: Submit `promo/show-hn.md` to Hacker News between 7:00 AM – 9:00 AM US Eastern (11:00 AM – 1:00 PM UTC) on a Tuesday or Wednesday.
- **Immediate Follow-up**: Post the pre-drafted first comment within 60 seconds of submission.
- **Goal**: Engage with systems engineers, discuss sliding window vs fixed buckets, and gather edge-case syslog feedback.

### Day 2: Dev.to Technical Deep Dive
- **Action**: Publish `promo/devto-article.md` on [dev.to](https://dev.to) under tags `#python`, `#security`, `#devops`, `#linux`.
- **Goal**: Establish search indexing and provide a thorough technical reference for anyone researching auth log parsing.

### Day 3: Weekly Newsletter Submissions
- **Action**: Submit the project blurbs from `promo/newsletters.md` to:
  - PyCoder's Weekly
  - Python Weekly
  - Console.dev
- **Goal**: Queue up inclusion in weekend digests.

### Day 4: Reddit – r/Python
- **Action**: Post `promo/reddit-python.md` to [r/Python](https://reddit.com/r/Python) with `Showcase` flair.
- **Timing**: Mid-morning US time.
- **Goal**: Discuss Python architectural choices (`collections.deque`, memory bounds, typing).

### Day 5: First Curated List PR
- **Action**: Open the Pull Request for `awesome-incident-response` using the template in `promo/awesome-lists.md`.
- **Goal**: Get indexed in the premier Blue Team reference repository.

### Day 6: Reddit – r/sysadmin
- **Action**: Post `promo/reddit-sysadmin.md` to [r/sysadmin](https://reddit.com/r/sysadmin).
- **Tone Check**: Ensure tone is humble and practical—focus on eliminating admin lockout risk and saving incident response time.

### Day 7: Sysadmin Curated List PR
- **Action**: Open the Pull Request for `kahun/awesome-sysadmin`.

### Day 8: Developer Tooling / Social Thread
- **Action**: Share a short technical walkthrough thread on Twitter / Mastodon / Bluesky with code snippets highlighting the compromise correlation heuristic.
- **Submit**: Console.dev tool recommendation.

### Day 9: Reddit – r/netsec
- **Action**: Post `promo/reddit-netsec.md` to [r/netsec](https://reddit.com/r/netsec).
- **Preparation**: Be ready for rigorous scrutiny on threat modeling, ReDoS guards, and false-positive rates.

### Day 10: Security Curated List PR
- **Action**: Open the Pull Request for `sbilly/awesome-security`.

### Day 11: Professional Networks (LinkedIn)
- **Action**: Share a concise writeup highlighting defensive open-source engineering, real-world Linux security, and the link to GitHub Releases.

### Day 12: Python Ecosystem Curated List PR
- **Action**: Open the Pull Request for `vinta/awesome-python` (verify alphabetical position).

### Day 13: Community Feedback Triage
- **Action**: Review all inbound GitHub Issues, Discussions, and PRs.
- **Milestone**: Tag good starter issues for new contributors and plan the v1.2.0 milestone (e.g. CEF/ECS formats, IPv6 expansion).

### Day 14: Retrospective & Metrics Review
- **Action**: Check GitHub Insights -> Traffic (clones, unique visitors, referring sites).
- **Document**: Note which channels drove the most engaged users and which feedback requires code improvements.
