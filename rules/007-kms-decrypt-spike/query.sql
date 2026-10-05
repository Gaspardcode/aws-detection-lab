-- threshold: 200
-- group: principal
-- Plus de 200 kms:Decrypt par heure et par principal (dernières 24 h).
SELECT useridentity.arn AS principal,
       date_trunc('hour', from_iso8601_timestamp(eventtime)) AS heure,
       count(*) AS n
FROM adl_logs.cloudtrail
WHERE eventname = 'Decrypt'
  AND eventsource = 'kms.amazonaws.com'
  AND day >= date_format(date_add('day', -1, current_date), '%Y/%m/%d')
GROUP BY 1, 2
HAVING count(*) > 200
ORDER BY n DESC
