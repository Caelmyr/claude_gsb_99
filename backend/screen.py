"""运营值守实时风险监控大屏 —— 内存滚动聚合分析层。

设计目标：
- 以引擎 WebSocket 监听器身份订阅每一条事件的决策结果，零侵入接入风控主链路；
- 仅在内存中维护「有界」聚合状态（小时桶 / 维度计数 / Top 主体 / 分钟速率 /
  告警播报队列），惰性淘汰过期数据，长时间运行内存不膨胀；
- 提供 24 小时滚动窗口的一次性快照（/api/screen/overview），大屏轮询拉取，
  实时性由 WebSocket 直推补充。

统计口径（与引擎保持一致）：
- 命中：至少一条规则 alpha+beta 全部命中（decision.matched）；
- 拦截：最终决策动作为 reject（展示口径，含直接拒绝与转人工复核）；
- 命中率 = 命中事件 / 总事件；拦截率 = 拦截事件 / 总事件。
"""
import threading
import time
from collections import deque

# 维度展示名（事件中出现的是原始 key）
COUNTRY_NAMES = {
    "CN": "中国", "US": "美国", "SG": "新加坡", "RU": "俄罗斯",
    "BR": "巴西", "NG": "尼日利亚", "HK": "中国香港", "JP": "日本",
    "KR": "韩国", "GB": "英国", "DE": "德国", "IN": "印度",
}
CHANNEL_NAMES = {
    "app": "APP", "h5": "H5", "openapi": "开放平台", "pc": "PC",
    "web": "Web", "mini": "小程序",
}
EVENT_TYPE_NAMES = {
    "login": "登录", "register": "注册", "order": "下单", "payment": "支付",
    "transfer": "转账", "withdraw": "提现", "sms": "短信", "api": "接口调用",
}
LEVEL_ORDER = ["严重", "高", "中", "低"]


def _hour_bucket(ts):
    """按北京时间（UTC+8）对齐到小时桶，返回桶起始 epoch 秒。"""
    shifted = ts + 8 * 3600
    start = int(shifted // 3600) * 3600
    return start - 8 * 3600


def _empty_hour():
    return {"total": 0, "matched": 0, "blocked": 0, "alerted": 0,
            "countries": {}, "channels": {}, "levels": {}, "types": {}}


class ScreenAnalytics:
    """大屏实时聚合器（线程安全，全部状态有界）。"""

    KEEP_HOURS = 25          # 多留 1 小时桶作为淘汰缓冲
    MAX_KEYS = 400           # IP / 用户维度键上限
    KEEP_KEYS = 300          # 触发淘汰后保留的键数
    MAX_FEED = 50            # 告警播报队列长度
    TOP_N = 10

    def __init__(self, top_n=None):
        if top_n:
            self.TOP_N = top_n
        self._lock = threading.RLock()
        self._hour_buckets = {}          # hour_ts -> 聚合桶
        self._ip_stats = {}              # ip -> 维度统计
        self._user_stats = {}            # user_id -> 维度统计
        self._minute_events = {}         # minute_ts -> 事件数（近实时速率）
        self._feed = []                  # 最新告警播报（新告警才入队）
        self._seen_feed_ids = set()
        # 引擎广播对同一监听器会重复投递一次，按事件 ID 短窗去重保证计数口径正确
        self._recent_ids = deque()
        self._recent_id_set = {}     # id -> 最近时间戳
        self._tick = 0

    # ------------------------------------------------------------------
    # 引擎事件订阅入口
    # ------------------------------------------------------------------
    def on_event(self, message):
        """engine._broadcast 消息监听器：仅消费 kind=event。"""
        if not isinstance(message, dict) or message.get("kind") != "event":
            return
        event = message.get("event") or {}
        decision = message.get("decision") or {}
        eid = event.get("id")
        now_ts = float(event.get("ts") or time.time())
        with self._lock:
            if eid is not None:
                # 仅短窗去重：引擎对同一监听器会连续双投递（间隔≈0），
                # 而仿真器高频注入可能产生跨秒的合法同 ID 事件，窗口不能放大
                recent = self._recent_id_set.get(eid)
                if recent is not None and now_ts - recent <= 2.0:
                    return
                self._recent_id_set[eid] = now_ts
                self._recent_ids.append((eid, now_ts))
                while len(self._recent_ids) > 20000:
                    old_id, _ = self._recent_ids.popleft()
                    self._recent_id_set.pop(old_id, None)
                cutoff = now_ts - 5
                while self._recent_ids and self._recent_ids[0][1] < cutoff:
                    old_id, _ = self._recent_ids.popleft()
                    if self._recent_id_set.get(old_id, 1e18) < cutoff:
                        self._recent_id_set.pop(old_id, None)
        try:
            self.record(event, decision)
        except Exception:
            # 大屏聚合属于旁路能力，任何异常都不能影响风控主链路
            pass

    def record(self, event, decision, feed=True):
        """记录一条已决策事件（启动回补与实时消费共用此入口）。"""
        ts = float(event.get("ts") or time.time())
        matched = bool(decision.get("matched"))
        blocked = decision.get("action") == "reject"
        score = int(decision.get("risk_score") or 0)
        alerts = decision.get("alerts") or []
        fired = {f.get("rule_id"): f for f in decision.get("fired_rules", [])}

        ip = event.get("ip")
        user = event.get("user_id")
        country = event.get("country")
        channel = event.get("channel")
        ev_type = event.get("type")
        level = None
        for ar in alerts:
            if ar.get("level"):
                level = ar["level"]
                break

        with self._lock:
            bucket = self._hour_buckets.setdefault(_hour_bucket(ts), _empty_hour())
            bucket["total"] += 1
            bucket["matched"] += 1 if matched else 0
            bucket["blocked"] += 1 if blocked else 0
            bucket["alerted"] += len(alerts)
            if country:
                bucket["countries"][country] = bucket["countries"].get(country, 0) + 1
            if channel:
                bucket["channels"][channel] = bucket["channels"].get(channel, 0) + 1
            if ev_type:
                bucket["types"][ev_type] = bucket["types"].get(ev_type, 0) + 1
            if level:
                bucket["levels"][level] = bucket["levels"].get(level, 0) + 1

            mb = int(ts // 60) * 60
            self._minute_events[mb] = self._minute_events.get(mb, 0) + 1

            if ip:
                self._bump_subject(self._ip_stats, ip, matched, blocked, score, ts)
            if user:
                self._bump_subject(self._user_stats, user, matched, blocked, score, ts)

            if feed:
                for ar in alerts:
                    if not ar.get("created", False):
                        continue
                    item = self._build_feed_item(ar, fired.get(ar.get("rule_id")),
                                                 event, ts)
                    if item and item["alert_id"] not in self._seen_feed_ids:
                        self._seen_feed_ids.add(item["alert_id"])
                        self._feed.append(item)
                if len(self._feed) > self.MAX_FEED:
                    self._feed = self._feed[-self.MAX_FEED:]
                    self._seen_feed_ids = {x["alert_id"] for x in self._feed}

            self._tick += 1
            if self._tick % 200 == 0:
                self._prune_locked(ts)

    @staticmethod
    def _bump_subject(store, key, matched, blocked, score, ts):
        st = store.get(key)
        if st is None:
            st = {"events": 0, "hits": 0, "blocked": 0, "score": 0, "last_seen": 0}
            store[key] = st
        st["events"] += 1
        st["hits"] += 1 if matched else 0
        st["blocked"] += 1 if blocked else 0
        st["score"] = max(st["score"], score)
        st["last_seen"] = ts

    @staticmethod
    def _build_feed_item(ar, fired, event, ts):
        aid = ar.get("alert_id") or ar.get("id")
        if not aid:
            return None
        subject = ar.get("subject") or {}
        item = {
            "alert_id": aid,
            "rule_id": ar.get("rule_id"),
            "rule_name": (fired or {}).get("rule_name") or ar.get("rule_name") or "",
            "reason": (fired or {}).get("reason") or ar.get("reason") or "",
            "level": ar.get("level") or "中",
            "score": int((fired or {}).get("risk_score") or ar.get("risk_score") or 0),
            "action": (fired or {}).get("action") or ar.get("action") or "alert",
            "count": ar.get("count", 1),
            "ip": subject.get("ip") or event.get("ip"),
            "user_id": subject.get("user_id") or event.get("user_id"),
            "country": event.get("country"),
            "channel": event.get("channel"),
            "type": event.get("type"),
            "ts": ts,
        }
        return item

    # ------------------------------------------------------------------
    # 惰性淘汰
    # ------------------------------------------------------------------
    def _prune_locked(self, now):
        cutoff_hour = _hour_bucket(now - (self.KEEP_HOURS - 1) * 3600)
        for hb in [h for h in self._hour_buckets if h < cutoff_hour]:
            self._hour_buckets.pop(hb, None)

        minute_cutoff = int(now // 60) * 60 - 300
        for mb in [m for m in self._minute_events if m < minute_cutoff]:
            self._minute_events.pop(mb, None)

        for store in (self._ip_stats, self._user_stats):
            if len(store) <= self.MAX_KEYS:
                continue
            ranked = sorted(
                store.items(),
                key=lambda kv: (self._risk_rank(kv[1]), kv[1]["last_seen"]),
                reverse=True)[:self.KEEP_KEYS]
            store.clear()
            store.update(ranked)

    @staticmethod
    def _risk_rank(st):
        """主体风险分：拦截量权重最高，叠加命中、事件量与峰值风险分。"""
        return st["blocked"] * 100 + st["hits"] * 20 + st["events"] + st["score"]

    # ------------------------------------------------------------------
    # 快照输出
    # ------------------------------------------------------------------
    def add_feed_item(self, item):
        """启动回补历史告警时使用。"""
        with self._lock:
            if item["alert_id"] in self._seen_feed_ids:
                return
            self._seen_feed_ids.add(item["alert_id"])
            self._feed.append(item)
            self._feed.sort(key=lambda x: x["ts"])
            if len(self._feed) > self.MAX_FEED:
                self._feed = self._feed[-self.MAX_FEED:]
                self._seen_feed_ids = {x["alert_id"] for x in self._feed}

    def backfill_alert(self, level, count, ts):
        """回补历史告警的小时桶计数（dry-run 不产生告警，需从已存储告警补齐）。"""
        with self._lock:
            bucket = self._hour_buckets.setdefault(_hour_bucket(ts), _empty_hour())
            bucket["alerted"] += max(1, int(count or 1))
            if level:
                bucket["levels"][level] = bucket["levels"].get(level, 0) + 1

    def overview(self, now=None):
        """返回 24 小时滚动窗口聚合快照。"""
        now = now or time.time()
        with self._lock:
            self._prune_locked(now)
            buckets = dict(self._hour_buckets)
            ip_stats = dict(self._ip_stats)
            user_stats = dict(self._user_stats)
            minutes = dict(self._minute_events)
            feed = list(self._feed)

        current_hour = _hour_bucket(now)
        hours = [current_hour - i * 3600 for i in range(23, -1, -1)]
        labels, total_s, matched_s, blocked_s, alerted_s = [], [], [], [], []
        countries, channels, levels, types_agg = {}, {}, {}, {}
        totals = {"total": 0, "matched": 0, "blocked": 0, "alerted": 0}

        for hb in hours:
            b = buckets.get(hb) or _empty_hour()
            d = time.gmtime(hb + 8 * 3600)
            labels.append(f"{d.tm_hour:02d}:00")
            total_s.append(b["total"])
            matched_s.append(b["matched"])
            blocked_s.append(b["blocked"])
            alerted_s.append(b["alerted"])
            totals["total"] += b["total"]
            totals["matched"] += b["matched"]
            totals["blocked"] += b["blocked"]
            totals["alerted"] += b["alerted"]
            for k, v in b["countries"].items():
                countries[k] = countries.get(k, 0) + v
            for k, v in b["channels"].items():
                channels[k] = channels.get(k, 0) + v
            for k, v in b.get("types", {}).items():
                types_agg[k] = types_agg.get(k, 0) + v
            for k, v in b["levels"].items():
                levels[k] = levels.get(k, 0) + v

        def top(store, dim):
            rows = sorted(store.items(),
                          key=lambda kv: (self._risk_rank(kv[1]), kv[1]["last_seen"]),
                          reverse=True)[:self.TOP_N]
            return [{dim: k, "name": k, "events": v["events"],
                     "hits": v["hits"], "blocked": v["blocked"],
                     "score": v["score"], "rank_score": self._risk_rank(v)}
                    for k, v in rows]

        # 近 60 秒事件速率（QPS）
        minute_cut = int(now // 60) * 60 - 60
        recent_events = sum(c for mb, c in minutes.items() if mb >= minute_cut)
        qps = round(recent_events / 60.0, 2)

        denom = totals["total"] or 0
        return {
            "generated_at": now,
            "kpi": {
                "total": totals["total"],
                "matched": totals["matched"],
                "blocked": totals["blocked"],
                "alerted": totals["alerted"],
                "hit_rate": round(totals["matched"] / denom, 4) if denom else 0,
                "block_rate": round(totals["blocked"] / denom, 4) if denom else 0,
                "qps": qps,
            },
            "trend": {
                "labels": labels,
                "total": total_s,
                "matched": matched_s,
                "blocked": blocked_s,
                "alerted": alerted_s,
            },
            "regions": [{"key": k, "name": COUNTRY_NAMES.get(k, k), "value": v}
                        for k, v in sorted(countries.items(),
                                           key=lambda kv: kv[1], reverse=True)],
            "channels": [{"key": k, "name": CHANNEL_NAMES.get(k, k), "value": v}
                         for k, v in sorted(channels.items(),
                                            key=lambda kv: kv[1], reverse=True)],
            "levels": [{"key": lv, "name": lv,
                        "value": levels.get(lv, 0)}
                       for lv in LEVEL_ORDER if levels.get(lv, 0) > 0],
            "types": [{"key": k, "name": EVENT_TYPE_NAMES.get(k, k), "value": v}
                      for k, v in sorted(types_agg.items(),
                                         key=lambda kv: kv[1], reverse=True)],
            "top_ips": top(ip_stats, "ip"),
            "top_users": top(user_stats, "user_id"),
            "feed": list(reversed(feed)),          # 最新在前
            "event_types": EVENT_TYPE_NAMES,
            "country_names": COUNTRY_NAMES,
            "channel_names": CHANNEL_NAMES,
        }


def backfill(engine, screen):
    """启动时回补：用近 24 小时已落盘事件重建趋势/分布/Top 榜，用内存告警重建播报。

    历史事件走 dry_run 只读匹配（不污染窗口、不重复告警/广播）；
    dry_run 返回引擎内部动作，需换算为展示口径（reject/review 均计为拦截）。
    """
    now = time.time()
    try:
        events = engine.events.query(start_ts=now - 86400, limit=100000)
    except Exception:
        events = []

    seen = set()
    for ev in events:
        eid = ev.get("id")
        if eid and eid in seen:
            continue
        if eid:
            seen.add(eid)
        try:
            d = engine.dry_run(ev)
        except Exception:
            continue
        internal_action = d.get("action")
        display_action = "reject" if internal_action in ("reject", "review") else \
            ("alert" if internal_action == "alert" else "pass")
        # 回补不产生新的告警播报项
        screen.record(ev, {
            "matched": d.get("matched"),
            "action": display_action,
            "risk_score": d.get("risk_score", 0),
            "alerts": [],
            "fired_rules": d.get("fired_rules", []),
        }, feed=False)

    # 历史告警（AlertAggregator 启动时已加载近两天分片）
    try:
        with engine.alerts._lock:
            alerts = list(engine.alerts._alerts.values())
    except Exception:
        alerts = []
    alerts = [a for a in alerts if a.get("first_seen", 0) >= now - 86400]
    alerts.sort(key=lambda a: a.get("first_seen", 0))
    for a in alerts:
        # 告警量 / 等级分布按已聚合告警记录补齐（count 为去重累加次数）
        screen.backfill_alert(a.get("level"), a.get("count", 1),
                              a.get("first_seen", now))
        subject = a.get("subject") or {}
        sample = a.get("event_sample") or {}
        screen.add_feed_item({
            "alert_id": a.get("id"),
            "rule_id": a.get("rule_id"),
            "rule_name": a.get("rule_name") or "",
            "reason": a.get("reason") or "",
            "level": a.get("level") or "中",
            "score": int(a.get("risk_score") or 0),
            "action": a.get("action") or "alert",
            "count": a.get("count", 1),
            "ip": subject.get("ip") or sample.get("ip"),
            "user_id": subject.get("user_id") or sample.get("user_id"),
            "country": sample.get("country"),
            "channel": sample.get("channel"),
            "type": sample.get("type"),
            "ts": a.get("first_seen", now),
        })
