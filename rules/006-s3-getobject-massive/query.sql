-- threshold: 100
-- group: principal
-- Plus de 100 lectures d'objets par heure et par principal sur le bucket patients (dernières 24 h).
SELECT useridentity.arn AS principal,
       date_trunc('hour', from_iso8601_timestamp(eventtime)) AS heure,
       count(*) AS n
FROM adl_logs.cloudtrail
WHERE eventname = 'GetObject'
  AND eventsource = 's3.amazonaws.com'
  AND json_extract_scalar(requestparameters, '$.bucketName') LIKE 'adl-patients-%'
  AND day >= date_format(date_add('day', -1, current_date), '%Y/%m/%d')
GROUP BY 1, 2
HAVING count(*) > 100
ORDER BY n DESC
