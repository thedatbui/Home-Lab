# Home-Lab

Application de shopping volontairement vulnérable pour pratiquer les risques
OWASP Top 10 dans un environnement local.

## Parcours produits et avis

- `/` présente les produits disponibles.
- `/product/1` affiche la fiche de la chaussure **Urban Runner** et ses avis.
- Un utilisateur connecté peut publier un avis depuis la fiche produit.
- `/admin` affiche les avis à modérer et exige un compte dont `role` vaut
  `admin`.

Le rendu des avis utilise volontairement `|safe` dans ce lab afin de fournir un
point d'entrée de XSS stockée sur la fiche produit et dans l'interface de
modération. Ne déployez pas cette application sur un réseau de production.

## Initialisation

Depuis la racine du projet :

```bash
flask --app app init-db
```

La commande recrée la base et insère les produits de démonstration. Pour
attribuer le rôle admin à un compte de laboratoire existant :

```sql
UPDATE user SET role = 'admin' WHERE username = 'admin';
```
