# 002 — Profil de connexion console

**Sévérité** : haute. **ATT&CK** : T1098.

## Vérifier
1. `requestParameters.userName` : cible de l'appel. Est-ce l'appelant lui-même (changement de mot de passe légitime) ou un autre compte ?
2. Une connexion console (`ConsoleLogin`) de cette cible a-t-elle suivi, depuis une IP inhabituelle ?

## Contenir
- Supprimer le profil de connexion (`aws iam delete-login-profile`), forcer la rotation des clés de la cible.
- Pas de réponse automatique (sévérité haute) : décision humaine.

## Faux positifs connus
Un administrateur qui réinitialise le mot de passe d'un collègue. Corréler avec le ticket.
