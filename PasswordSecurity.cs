using System.Text;
using System.Security.Cryptography;

namespace GlobalSecurityNuget;

/// <summary>
/// Class contenant les méthodes concernant les mots de passe
/// </summary>
public static class PasswordSecurity
{
    /// <summary>
    /// Permet de hasher un mot de passe en SHA512 en utilisant la méthode dite "Sel/Poivre".
    /// Le sel correspond à la clé publique et le poivre à la clé privée.
    /// </summary>
    /// <param name="privateKey">Clé privée qui est identique pour tous vos mots de passe</param>
    /// <param name="publicKey">Clé publique qui est unique pour chaque mot de passe</param>
    /// <param name="password">Mot de passe en clair</param>
    /// <returns></returns>
    public static string Hash512(string privateKey, string publicKey, string password)
    {
        // Convertir le mot de passe en tableau de bytes
        byte[] passwordBytes = Encoding.UTF8.GetBytes($"{publicKey}{password}{privateKey}");

        // Calculer le hash SHA-512
        byte[] hashBytes = SHA512.HashData(passwordBytes);
        hashBytes = SHA512.HashData(hashBytes);

        // Convertir le hash en une chaîne hexadécimale
        StringBuilder hashStringBuilder = new();
        foreach (byte b in hashBytes)
        {
            hashStringBuilder.Append(b.ToString("x2"));
        }

        return hashStringBuilder.ToString();
    }

    private const int SaltSize = 16; // Taille du sel en octets
    private const int Iterations = 10000; // Nombre d'itérations

    /// <summary>
    /// Permet de hasher votre mot de passe en utilisant la méthode RFC2898, qui est une implémentation de PBKDF2.
    /// </summary>
    /// <param name="password">Mot de passe en clair</param>
    /// <returns></returns>
    public static string HashRFC2898(string password)
    {
        // Générer un sel aléatoire
        byte[] salt = new byte[SaltSize];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        // Hacher le mot de passe
        using var hasher = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA512);
        byte[] hashBytes = hasher.GetBytes(32); // Taille du hash en octets

        // Concaténer le sel et le hash pour le stockage
        byte[] result = new byte[SaltSize + hashBytes.Length];
        Buffer.BlockCopy(salt, 0, result, 0, SaltSize);
        Buffer.BlockCopy(hashBytes, 0, result, SaltSize, hashBytes.Length);

        // Convertir le résultat en une chaîne hexadécimale
        return BitConverter.ToString(result).Replace("-", string.Empty);
    }

    /// <summary>
    /// Permet de vérifier la correspondance entre votre hash et votre mot de passe en clair pour la méthode RFC2898.
    /// </summary>
    /// <param name="hashedPassword">Mot de passe hashé</param>
    /// <param name="inputPassword">Mot de passe en clair</param>
    /// <returns></returns>
    public static bool VerifyRFC2898(string hashedPassword, string inputPassword)
    {
        // Convertir la chaîne hexadécimale en bytes
        byte[] hashedPasswordBytes = new byte[hashedPassword.Length / 2];
        for (int i = 0; i < hashedPasswordBytes.Length; i++)
        {
            hashedPasswordBytes[i] = Convert.ToByte(hashedPassword.Substring(i * 2, 2), 16);
        }

        // Extraire le sel à partir du hash
        byte[] salt = new byte[SaltSize];
        Buffer.BlockCopy(hashedPasswordBytes, 0, salt, 0, SaltSize);

        // Utiliser Argon2 pour vérifier le mot de passe
        using var hasher = new Rfc2898DeriveBytes(inputPassword, salt, Iterations, HashAlgorithmName.SHA512);
        byte[] hashBytes = hasher.GetBytes(32);

        // Comparer les deux hashes
        for (int i = 0; i < hashBytes.Length; i++)
        {
            if (hashBytes[i] != hashedPasswordBytes[i + SaltSize])
            {
                return false;
            }
        }

        return true;
    }
}
