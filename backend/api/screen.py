"""运营值守实时风险监控大屏 API。"""
from flask import Blueprint, jsonify

from backend import runtime
from backend.auth import login_required

bp = Blueprint("screen", __name__, url_prefix="/api/screen")


@bp.route("/overview", methods=["GET"])
@login_required
def overview():
    """24 小时滚动窗口聚合快照（KPI / 趋势 / 分布 / Top 榜 / 告警播报）。"""
    data = runtime.screen.overview()
    # 补充待处置告警数（来自引擎告警聚合器）
    try:
        a_stats = runtime.engine.alerts.stats()
        data["open_alerts"] = a_stats.get("by_status", {}).get("new", 0)
        data["ack_alerts"] = a_stats.get("by_status", {}).get("acked", 0)
        data["engine"] = runtime.engine.registry.current.describe()
    except Exception:
        data["open_alerts"] = 0
        data["ack_alerts"] = 0
    return jsonify({"ok": True, "data": data})
