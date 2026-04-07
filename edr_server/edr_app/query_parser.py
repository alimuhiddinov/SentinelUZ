"""
SentinelUZ Query Language
Supports: field:value AND OR NOT grouping ()
"""
import re
from datetime import datetime
from django.utils import timezone
from django.db.models import Q


class QueryParser:

    EVENT_FIELD_MAP = {
        'type':     'event_type__iexact',
        'host':     'client__hostname__icontains',
        'hostname': 'client__hostname__icontains',
        'ip':       'raw_data__icontains',
        'process':  'raw_data__icontains',
        'pid':      'raw_data__icontains',
        'hash':     'raw_data__icontains',
        'chain':    'raw_data__icontains',
    }

    ALERT_FIELD_MAP = {
        'severity': 'severity__iexact',
        'type':     'type__icontains',
        'host':     'client__hostname__icontains',
        'hostname': 'client__hostname__icontains',
        'ioc':      'ioc_matched__icontains',
        'status':   'status__iexact',
        'process':  'process_name__icontains',
    }

    def __init__(self, query_string, mode='events'):
        self.raw = query_string.strip()
        self.mode = mode
        self.field_map = (self.EVENT_FIELD_MAP
                          if mode == 'events'
                          else self.ALERT_FIELD_MAP)

    def parse(self):
        if not self.raw:
            return Q(), {}
        tokens = self._tokenize(self.raw)
        q, date_filters = self._build_q(tokens)
        return q, date_filters

    def _tokenize(self, s):
        pattern = (r'\(|\)|'
                   r'(?:AND|OR|NOT)\b|'
                   r'\w+:[^\s()]+|'
                   r'"[^"]+"|'
                   r'\S+')
        return re.findall(pattern, s, re.IGNORECASE)

    def _build_q(self, tokens):
        date_filters = {}
        q_parts = []
        operators = []
        i = 0

        while i < len(tokens):
            tok = tokens[i]
            upper = tok.upper()

            if upper in ('AND', 'OR', 'NOT'):
                operators.append(upper)
                i += 1
                continue

            if tok == '(':
                depth = 1
                j = i + 1
                while j < len(tokens) and depth > 0:
                    if tokens[j] == '(':
                        depth += 1
                    elif tokens[j] == ')':
                        depth -= 1
                    j += 1
                sub_q, sub_dates = self._build_q(tokens[i+1:j-1])
                date_filters.update(sub_dates)
                q_parts.append(sub_q)
                i = j
                continue

            if tok == ')':
                i += 1
                continue

            if ':' in tok:
                field, _, value = tok.partition(':')
                field = field.lower()
                value = value.strip('"')

                if field == 'after':
                    try:
                        date_filters['after'] = datetime.strptime(
                            value, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
                    i += 1
                    continue

                if field == 'before':
                    try:
                        date_filters['before'] = datetime.strptime(
                            value, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
                    i += 1
                    continue

                if field in self.field_map:
                    lookup = self.field_map[field]
                    q_parts.append(Q(**{lookup: value}))
                else:
                    q_parts.append(self._generic_q(value))
            else:
                q_parts.append(self._generic_q(tok))

            i += 1

        return self._combine(q_parts, operators), date_filters

    def _combine(self, parts, operators):
        if not parts:
            return Q()
        result = parts[0]
        for i, part in enumerate(parts[1:]):
            op = operators[i] if i < len(operators) else 'AND'
            if op == 'OR':
                result = result | part
            elif op == 'NOT':
                result = result & ~part
            else:
                result = result & part
        return result

    def _generic_q(self, value):
        if self.mode == 'events':
            return (
                Q(event_type__icontains=value) |
                Q(client__hostname__icontains=value) |
                Q(raw_data__icontains=value)
            )
        else:
            return (
                Q(type__icontains=value) |
                Q(ioc_matched__icontains=value) |
                Q(process_name__icontains=value) |
                Q(client__hostname__icontains=value) |
                Q(description__icontains=value)
            )


def apply_query(qs, query_string, mode='events'):
    if not query_string or not query_string.strip():
        return qs, {}
    parser = QueryParser(query_string, mode)
    q, date_filters = parser.parse()
    if q:
        qs = qs.filter(q)
    ts_field = 'timestamp' if mode == 'events' else 'last_seen'
    if date_filters.get('after'):
        qs = qs.filter(**{f'{ts_field}__gte': date_filters['after']})
    if date_filters.get('before'):
        qs = qs.filter(**{f'{ts_field}__lte': date_filters['before']})
    return qs, date_filters
