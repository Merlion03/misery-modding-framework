using System;
using System.Text.RegularExpressions;

namespace Misery.ModAPI
{
    /// <summary>
    /// A mod's identity. The one authoritative namespace in the framework.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the C# face of the canonical ModId contract that
    /// <c>tools/modplatform/modid.py</c> defines and that the Stage 2 item
    /// registry and the Stage 3 asset pipeline both consume. The rule is stated
    /// in one place and mirrored here; a test compares the pattern, the length
    /// limit, the separator and the reserved set across all three surfaces,
    /// because three copies of a rule nobody compares is exactly how the
    /// original drift between stages happened.
    /// </para>
    /// <para>
    /// A mod never constructs one of these for itself out of thin air and hands
    /// it to the framework: it receives its own from
    /// <see cref="IModContext.Id"/>. The public constructor exists so a mod can
    /// name ANOTHER mod -- to declare a dependency or bind a service -- and it
    /// validates, because a malformed id reaching the native side would be a
    /// malformed row name or package path further down.
    /// </para>
    /// <para>
    /// It is a readonly struct wrapping a string rather than a bare string so
    /// that a method taking a ModId cannot be handed an arbitrary string by
    /// mistake. Stringly-typed identity is how one mod ends up acting under
    /// another's name.
    /// </para>
    /// </remarks>
    public readonly struct ModId : IEquatable<ModId>
    {
        /// <summary>The syntax rule. Mirrors <c>modid.PATTERN_TEXT</c>.</summary>
        public const string PatternText = "^[a-z][a-z0-9_]*$";

        /// <summary>
        /// Separates a mod id from a local item id in a derived row name.
        /// Neither half may contain it, which is what makes the decomposition
        /// unambiguous.
        /// </summary>
        public const string Separator = "__";

        /// <summary>Mirrors <c>modid.MAX_LENGTH</c>.</summary>
        public const int MaxLength = 48;

        private static readonly Regex Pattern =
            new Regex(PatternText, RegexOptions.CultureInvariant);

        /// <summary>
        /// Names a mod may not take, because holding one would let it
        /// impersonate the game or the framework. Mirrors
        /// <c>modid.RESERVED</c> exactly.
        /// </summary>
        public static readonly string[] Reserved =
        {
            "core", "engine", "game", "misery", "mods", "script", "sgk",
            "temp", "vanilla"
        };

        private readonly string _value;

        /// <summary>Validates and wraps <paramref name="value"/>.</summary>
        /// <exception cref="ArgumentException">The id breaks the contract.</exception>
        public ModId(string value)
        {
            string reason = Validate(value);
            if (reason != null)
            {
                throw new ArgumentException(
                    "'" + value + "' is not a valid ModId: " + reason, nameof(value));
            }

            _value = value;
        }

        /// <summary>The id, or null for a default-constructed value.</summary>
        public string Value => _value;

        /// <summary>True when this is a real id rather than <c>default</c>.</summary>
        public bool IsValid => _value != null;

        /// <summary>
        /// Why <paramref name="value"/> is not a legal id, or null if it is.
        /// Returning the reason rather than a bool means a caller can tell a
        /// user WHICH rule was broken.
        /// </summary>
        public static string Validate(string value)
        {
            if (value == null)
            {
                return "it is null";
            }

            if (value.Length == 0)
            {
                return "it is empty";
            }

            if (value.Length > MaxLength)
            {
                return "it is longer than " + MaxLength + " characters";
            }

            if (!Pattern.IsMatch(value))
            {
                return "it does not match " + PatternText +
                       " -- engine name comparison is case-insensitive, so two " +
                       "ids differing only in case would be one name to the game";
            }

            if (value.Contains(Separator))
            {
                return "it contains '" + Separator +
                       "', which separates a mod id from a local item id";
            }

            if (Array.IndexOf(Reserved, value) >= 0)
            {
                return "it is reserved";
            }

            return null;
        }

        /// <summary>True when <paramref name="value"/> is a legal id.</summary>
        public static bool IsValidId(string value) => Validate(value) == null;

        /// <summary>
        /// The row name the game will see for one of this mod's items.
        /// Derived, never authored: a mod cannot choose a row name and
        /// therefore cannot land on a vanilla one or another mod's.
        /// </summary>
        public string RowName(string localId)
        {
            if (!IsValid)
            {
                throw new InvalidOperationException("this ModId is not initialised");
            }

            string reason = ValidateLocalId(localId);
            if (reason != null)
            {
                throw new ArgumentException(
                    "'" + localId + "' is not a valid local id: " + reason,
                    nameof(localId));
            }

            return _value + Separator + localId;
        }

        /// <summary>
        /// The local half of a row name, held to the same syntax rule but NOT
        /// to the reserved-name rule: a local id is already namespaced by the
        /// mod that declared it, so "core" inside <c>alphamod</c> impersonates
        /// nothing -- its row name is <c>alphamod__core</c>.
        /// </summary>
        public static string ValidateLocalId(string localId)
        {
            if (localId == null)
            {
                return "it is null";
            }

            if (localId.Length == 0)
            {
                return "it is empty";
            }

            if (localId.Length > MaxLength)
            {
                return "it is longer than " + MaxLength + " characters";
            }

            if (!Pattern.IsMatch(localId))
            {
                return "it does not match " + PatternText;
            }

            if (localId.Contains(Separator))
            {
                return "it contains '" + Separator +
                       "'; the row name would decompose to a different mod";
            }

            return null;
        }

        /// <inheritdoc />
        public bool Equals(ModId other) =>
            string.Equals(_value, other._value, StringComparison.Ordinal);

        /// <inheritdoc />
        public override bool Equals(object obj) => obj is ModId other && Equals(other);

        /// <inheritdoc />
        public override int GetHashCode() => _value == null ? 0 : _value.GetHashCode();

        /// <inheritdoc />
        public override string ToString() => _value ?? "<none>";

        /// <summary>Value equality.</summary>
        public static bool operator ==(ModId left, ModId right) => left.Equals(right);

        /// <summary>Value inequality.</summary>
        public static bool operator !=(ModId left, ModId right) => !left.Equals(right);
    }
}
