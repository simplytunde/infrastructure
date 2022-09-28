# Company Infrastructure

```
export AWS_PROFILE="default"
export KUBECONFIG=~/.kube/wuralab
aws eks update-kubeconfig --region us-west-1 --name wuralab
kubectl get no
```

### Install Controller for Load Balancer
```
helm install --create-namespace  ingress-nginx ingress-nginx/ -f ingress-nginx/override.yaml -n ingress-nginx
kubectl get service -n ingress-nginx
```

### Install Company Application
```
helm install --create-namespace appsmith appsmith/ -n appsmith
```

### Uninstall Applications
```
helm del appsmith -n appsmith
helm del ingress-nginx -n ingress-nginx
```