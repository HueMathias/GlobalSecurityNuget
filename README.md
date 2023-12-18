# Présentation

Ce Nuget permet d'améliorer la sécurité de votre application.

# Mots de passe

La class **PasswordSecurity** permet fournie des méthodes pour sécuriser vos mots de passe.

* Hash512 : Permet de hasher en SHA512 avec une méthode de salage
* HashRFC2898 : Permet de hasher avec la méthode RFC2898
* VerifyRFC2898 : Permet de vérifier un mot de passe en comparant le mot de passe hashé et le mot de passe en clair