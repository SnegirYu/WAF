"""
Семантический анализ запроса: когда API не может осмысленно обработать намерение клиента.
"""
from __future__ import annotations

from django.http import HttpRequest


def teapot_detail_for_request(request: HttpRequest) -> str | None:
    """
    RFC 2324 / HTCPCP: запрос требует действия, которое WAF API выполнить не может
    (заварить кофе, протокол чайника и т.п.). Возвращает текст для Problem Details или None.
    """
    method = request.method.upper()
    if method == "BREW":
        return (
            "Метод BREW (HTCPCP) не применим: API управления WAF не является чайником "
            "и не выполняет заваривание напитков."
        )

    content_type = request.META.get("CONTENT_TYPE", "").lower()
    for token in ("application/coffee", "application/teapot", "application/htcpecp"):
        if token in content_type:
            return (
                f"Тип содержимого «{content_type}» не обрабатывается API. "
                "Запрос отклонён: сервер не умеет выполнять данное действие."
            )

    accept = request.META.get("HTTP_ACCEPT", "").lower()
    if accept.strip() in ("application/coffee", "application/coffee,*/*"):
        return (
            "Заголовок Accept требует application/coffee, но API отдаёт только JSON. "
            "Сервер не знает, как выполнить запрошенное представление ответа."
        )

    if request.META.get("HTTP_BREW_METHOD") or request.META.get("HTTP_BREW"):
        return (
            "Заголовки заваривания (Brew-Method / Brew) не поддерживаются REST API WAF."
        )

    brew_q = request.GET.get("brew", "").lower()
    if brew_q in ("coffee", "espresso", "latte"):
        return (
            f"Параметр brew={brew_q} не относится к API WAF. "
            "Сервер не может выполнить запрошенное действие."
        )

    if request.GET.get("intent", "").lower() in ("brew_coffee", "make_coffee", "brew"):
        return "Параметр intent описывает действие, которое API WAF не реализует."

    return None
