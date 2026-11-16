# 📦 Gestionnaire d'inventaire

Application web de gestion d'inventaire **multi-utilisateurs**, prête à héberger gratuitement en ligne.

- **Articles** : photo, nom, description, prix de vente, prix coûtant, SKU, catégorie, stock et seuil d'alerte de stock bas.
- **Mouvements** : entrées (+), ventes et sorties (−) avec quantité, prix, note, utilisateur et date. Boutons rapides ×5 / ×10.
- **Tableau de bord** : ventes du jour et du mois, valeur du stock, alertes stock bas / rupture, articles les plus vendus, graphiques journalier (30 jours) et mensuel (12 mois), historique filtrable.
- **Factures (facultatives)** : une case à cocher pendant une vente, ou un onglet dédié (client, lignes, taxes, numéro auto `FAC-AAAA-0001`, impression / PDF). Les ventes fonctionnent très bien sans facture.
- **Comptes et rôles** : Admin (catalogue, prix, photos, utilisateurs), Employé (ventes, factures, stock), Lecture seule (consulte seulement).
- **Sauvegarde** : export et import de toutes les données en JSON, depuis l'onglet Sauvegarde.

**Technique** : Node.js + Express + SQLite intégré (`node:sqlite`, aucune compilation). Interface en HTML/CSS/JS vanilla, aucune étape de build, aucune dépendance payante.

---

## 🚀 Déployer gratuitement en ligne (Render)

### Étape 1 — Mettre le code sur GitHub (gratuit)

1. Créez un compte gratuit sur [github.com](https://github.com) si ce n'est pas déjà fait.
2. Créez un nouveau dépôt (bouton **New**), par exemple `gestionnaire-inventaire`, en **Public**.
3. Sur votre ordinateur, dans le dossier du projet :
   ```bash
   git init
   git add .
   git commit -m "Gestionnaire d'inventaire"
   git branch -M main
   git remote add origin https://github.com/VOTRE_NOM/gestionnaire-inventaire.git
   git push -u origin main
   ```
   (Remplacez `VOTRE_NOM` par votre nom d'utilisateur GitHub. GitHub vous demandera de vous connecter.)
4. Alternative sans ligne de commande : sur la page du dépôt, cliquez sur **Add file → Upload files** et glissez-y tous les fichiers du projet.

> ⚠️ Ne mettez **jamais** le fichier `data.sqlite` sur GitHub : il contient vos données et les mots de passe. Il est déjà ignoré grâce au fichier `.gitignore` fourni.

### Étape 2 — Créer un compte Render (gratuit)

1. Allez sur [render.com](https://render.com) et créez un compte gratuit (vous pouvez vous connecter avec GitHub, c'est le plus simple).
2. Aucune carte bancaire n'est demandée pour l'offre gratuite.

### Étape 3 — Créer le Web Service

1. Sur Render, cliquez sur **New + → Web Service**.
2. Choisissez **Build and deploy from a Git repository** et sélectionnez votre dépôt `gestionnaire-inventaire`.
3. Render détecte le fichier `render.yaml` et remplit tout automatiquement :
   - **Environment** : Node
   - **Build Command** : `npm install`
   - **Start Command** : `npm start`
   - **Plan** : Free
4. Cliquez sur **Create Web Service**. Le déploiement prend 2 à 3 minutes.
5. Quand le statut passe à **Live**, cliquez sur l'adresse (du type `https://gestionnaire-inventaire.onrender.com`) : votre application est en ligne ! 🎉

### Étape 4 — Première connexion

1. Ouvrez l'adresse de votre application.
2. Connectez-vous avec :
   - **Identifiant :** `admin`
   - **Mot de passe :** `admin123`
3. L'application vous demandera immédiatement de **choisir un nouveau mot de passe** : faites-le, c'est important.
4. Allez dans l'onglet **Équipe & rôles** pour créer les comptes de vos employés (rôle Employé ou Lecture seule).

Partagez ensuite simplement l'adresse à votre équipe : tout le monde se connecte en même temps, sur téléphone, tablette ou ordinateur, et voit les mêmes chiffres en temps réel.

---

## 💻 Lancer en local (sur votre ordinateur)

Prérequis : Node.js 22 ou plus ([nodejs.org](https://nodejs.org)).

```bash
npm install
node server.js
```

Ouvrez ensuite [http://localhost:3000](http://localhost:3000) dans votre navigateur.
Connexion initiale : `admin` / `admin123` (à changer à la première connexion).

Les données sont enregistrées dans le fichier `data.sqlite`, créé automatiquement à côté de `server.js`.

---

## ⚠️ Limites de l'offre gratuite (à connaître)

- **Disque éphémère** : sur Render gratuit, le fichier de données peut être effacé quand le service redémarre ou est redéployé.
  → **Exportez vos données régulièrement** depuis l'onglet **Sauvegarde** (bouton « Exporter en JSON ») et gardez le fichier précieusement. En cas de perte, restaurez-le avec « Restaurer une sauvegarde ».
- **Mise en veille** : après environ 15 minutes sans visite, le service gratuit s'endort. La première ouverture après une pause prend 30 à 60 secondes (le temps qu'il se réveille), puis tout redevient normal.
- **Un seul service gratuit à la fois** sur certains comptes Render : si vous avez déjà un service gratuit, il faudra peut-être en supprimer un.
- **Photos** : les photos sont stockées en base64 dans la base de données (c'est fait exprès pour survivre aux disques éphémères). Elles sont automatiquement réduites à 800 px pour ne pas alourdir la base.

---

## 🔐 Sécurité — à faire après l'installation

- Changez le mot de passe `admin123` dès la première connexion (l'application l'exige).
- Donnez à chaque personne son propre compte (onglet Équipe & rôles) : ne partagez pas le compte admin.
- Gardez vos fichiers d'export JSON dans un endroit sûr : ils contiennent toutes vos données.
- Pour passer à une offre payante plus tard (données persistantes, pas de mise en veille), Render propose des plans à quelques dollars par mois, sans rien changer au code.

## 📁 Fichiers du projet

| Fichier | Rôle |
|---|---|
| `server.js` | Serveur : API, base de données, authentification, factures |
| `public/index.html` | Page de l'application |
| `public/app.js` | Logique de l'interface (onglets, formulaires, graphiques) |
| `public/style.css` | Mise en page, mobile-friendly |
| `package.json` | Dépendances et commande de démarrage |
| `render.yaml` | Déploiement en un clic sur Render |
| `.gitignore` | Empêche d'envoyer la base de données sur GitHub |
| `README.md` | Ce guide |
