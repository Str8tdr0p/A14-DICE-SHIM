rule Silicon_Rooted_Identity_Exfiltration_Stepped_On_Silicon {
    meta:
        description = "Detects hardware-rooted identity decoupling and exfiltration markers — Project Stepped-On Silicon"
        author = "Joseph Goydish II & Ace Gunner / Stepped-On Silicon Research"
        reference = "Project DICE-SHIM: Hardware-Enforced Identity Decoupling"
        date = "2026-02-14"
        severity = "Critical"
        cvss_score = "10.0"

    strings:
        /* Hardware Attestation / TCCDI Tokens */
        $tccdi_sig = { 52 58 01 11 } 
        $tccdi_header = { 52 58 01 11 EC 28 00 40 26 00 F8 A2 B8 08 13 75 }
        $identity_secret = "TCCDI" wide ascii
        
        /* State-Aware Triggers (User Inactivity/UI) */
        $ui_trigger_1 = "SBBanner" wide ascii
        $ui_trigger_2 = "setScreenOff:YES" wide ascii
        $ui_trigger_3 = "suggestedPortraitPresentationMode: Static" wide ascii
        $eval_logic = "eval"

        /* Telemetry Mirroring (WombatStream / Transcript Fragments) */
        $telemetry_1 = ": Will not queue" wide ascii
        $telemetry_2 = "- autojoin" wide ascii
        $telemetry_3 = "Applier: currF" wide ascii
        $telemetry_4 = "UpInRecei" wide ascii

        /* Exfiltration Infrastructure Indicators */
        $c2_endpoint = "kaylees.site"
        $egress_marker = "satisfied (Path is ready)" wide ascii

    condition:
        /* High-fidelity match for identity secrets alongside exfiltration or UI triggers */
        ((uint32(0) == 0x11015852 or $tccdi_header or $tccdi_sig) and 
        (any of ($ui_trigger*) or any of ($telemetry*) or ($c2_endpoint and $egress_marker))) or
        ($sb_banner and $portrait_mode and $eval_logic)
}
