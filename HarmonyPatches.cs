using System;
using HarmonyLib;
using Il2Cpp;
using Il2CppBestHTTP;
using Il2CppOrg.BouncyCastle.Crypto.Tls;
using Il2CppPhoton.Realtime;
using Il2CppRecRoom.AntiCheat;
using Il2CppRecRoom.Core.Creation;
using MelonLoader;
using Mocha.Patch;
using Uri = Il2CppSystem.Uri;

namespace MochaPatches
{
    public class HarmonyPatches
    {
        [HarmonyPatch(typeof(HTTPManager), "SendRequest", new Type[]
        {
            typeof(HTTPRequest)
        })]
        internal class NSPatch
        {
            private static void Prefix(ref HTTPRequest request)
            {
                bool flag = request.Uri.ToString().Contains("ns.rec.net");
                if (flag)
                {
                    request.Uri = new Uri("https://playmocha.xyz/nameserver");
                }
                Uri uri = request.Uri;
                MelonLogger.Msg("Caught request: " + ((uri != null) ? uri.ToString() : null));

                request.SetHeader("X-Mocha-SteamId", SteamCache.CachedSteamId64);
                request.SetHeader("X-Mocha-Build", Core.ModVersion);
                request.SetHeader("X-Mocha-Sig", Integrity.LastSnapshot);
            }
        }

        [HarmonyPatch(typeof(PUNNetworkManager), "AALEDKJKEPO")]
        internal class PhotonPatch
        {
            private static void Postfix(ref AppSettings __result)
            {
                __result = new AppSettings
                {
                    AppIdRealtime = PhotonConnection.RealtimeAppId,
                    AppIdVoice = PhotonConnection.VoiceAppId,
                    AppVersion = PhotonConnection.AppVersion,
                    FixedRegion = PhotonConnection.Region
                };
            }
        }

        [HarmonyPatch(typeof(EDNHOPAGKLC), "MGKINLFMJLB")]
        internal class PhotonPatch2
        {
            private static void Postfix(ref AppSettings __result)
            {
                __result = new AppSettings
                {
                    AppIdRealtime = PhotonConnection.RealtimeAppId,
                    AppIdVoice = PhotonConnection.VoiceAppId,
                    AppVersion = PhotonConnection.AppVersion,
                    FixedRegion = PhotonConnection.Region
                };
            }
        }

        [HarmonyPatch(typeof(HPEENKELKDJ), "MGKINLFMJLB")]
        internal class PhotonPatch3
        {
            private static void Postfix(ref AppSettings __result)
            {
                __result = new AppSettings
                {
                    AppIdRealtime = PhotonConnection.RealtimeAppId,
                    AppIdVoice = PhotonConnection.VoiceAppId,
                    AppVersion = PhotonConnection.AppVersion,
                    FixedRegion = PhotonConnection.Region
                };
            }
        }

        [HarmonyPatch(typeof(LegacyTlsAuthentication), "NotifyServerCertificate")]
        internal class AlwaysVerifyTLSPatch
        {
            private static bool Prefix()
            {
                return false;
            }
        }

        [HarmonyPatch(typeof(EACManager), "GenerateChallengeResponse")]
        internal class EACPatch
        {
            private static bool Prefix(ref string __result)
            {
                __result = "\"AQAAAGd9O3h2ynQW6Y/1MhdZC8VoHygxyTzmiRvAfpiRtJEBQ+NVaXMStRTsYQk42H1hbB7NGKhIpgfShk+ADtRW9EU/YF5320eGmINJZAqkm3pyX9QF/w1QT4IB2EQfOqTfpryQ3QFchXYqDgg/SbX+/X9mgzssbflIw3OAK+c=\"";
                return false;
            }
        }

        // GetErrorDescription (RecRoom.Core.Creation.CreationManager) is the string
        // formatter called whenever a Creation Op (SpawnInvention, etc.) comes back
        // as anything other than success. It's a big switch over the numeric result
        // code. Real maker-pen objects (which carry a non-zero InstantiationCost)
        // route through a room-instantiation-budget check before this point that
        // Mocha's server never sends any budget data for, and whatever code that
        // path produces isn't one this switch has a safe case for - it throws
        // (InvalidOperationException: "Nullable object must have a value") instead
        // of returning a string, which is why every real-object spawn shows the
        // "Error Error" crash. Circuits carry zero InstantiationCost and never hit
        // that path, which is why they always worked.
        //
        // This can't be fixed server-side: the crash is inside the client's own
        // result-code formatter, not in anything Mocha returns over HTTP. Patching
        // it here so a bad code degrades to a real message instead of crashing the
        // whole creation flow.
        [HarmonyPatch(typeof(CreationManager), "GetErrorDescription")]
        internal class CreationErrorDescriptionGuard
        {
            private static Exception Finalizer(Exception __exception, ref string __result)
            {
                if (__exception != null)
                {
                    MelonLogger.Warning("[MochaPatches] GetErrorDescription crashed, using fallback: " + __exception);
                    __result = "Spawn failed (unrecognized result)";
                }
                return null;
            }
        }
    }
}
