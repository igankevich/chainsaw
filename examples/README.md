# Examples for nginx and grafana images

## For nginx
```bash
cd nginx
docker build -t nginx-cropped .
docker run --name nginx-c nginx-cropped
```

## For grafana
```bash
cd grafana
docker build -t grafana-cropped .
docker run --name graf-c -p 3000:3000 grafana-cropped
```