-- threshold: 500000000
-- group: instance
-- Plus de 500 Mo vers des adresses non privées par heure et par instance (dernières 24 h).
SELECT instance_id AS principal,
       date_trunc('hour', from_unixtime("start")) AS heure,
       sum(bytes) AS n
FROM adl_logs.vpc_flow_logs
WHERE flow_direction = 'egress'
  AND action = 'ACCEPT'
  AND NOT (   regexp_like(dstaddr, '^10\.')
           OR regexp_like(dstaddr, '^192\.168\.')
           OR regexp_like(dstaddr, '^172\.(1[6-9]|2[0-9]|3[01])\.'))
  AND year = year(current_date)
  AND from_unixtime("start") >= date_add('day', -1, current_timestamp)
GROUP BY 1, 2
HAVING sum(bytes) > 500000000
ORDER BY n DESC
