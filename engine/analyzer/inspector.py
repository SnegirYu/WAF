from .request_types import ParsedRequest, InspectionResult
from .signatures import sqli, xss, traversal
from .heuristics import anomalies

def analyze_request(request: ParsedRequest) -> InspectionResult:
    """
    Главная точка входа для сервера
    """
    
    # сигнатурные проверки
    
    is_sqli, details = sqli.check(request)
    if is_sqli:
        return InspectionResult(is_safe=False, action='block', reason='SQL_INJECTION', details=details)
        
    is_xss, details = xss.check(request)
    if is_xss:
        return InspectionResult(is_safe=False, action='block', reason='XSS', details=details)
        
    is_traversal, details = traversal.check(request)
    if is_traversal:
        return InspectionResult(is_safe=False, action='block', reason='PATH_TRAVERSAL', details=details)

    # эвристические проверки
    is_anomaly, details = anomalies.check(request)
    if is_anomaly:
        return InspectionResult(is_safe=False, action='block', reason='ANOMALY', details=details)

    return InspectionResult(is_safe=True, action='allow')