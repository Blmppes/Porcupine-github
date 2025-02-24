/*
Generated by Yara-Rules
On 12-04-2022
*/
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/antidebug_antivm/antidebug_antivm.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/capabilities/capabilities.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/crypto/crypto_signatures.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2010-0805.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2010-0887.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2010-1297.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2012-0158.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2013-0074.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2013-0422.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2015-1701.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2015-2426.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2015-2545.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2015-5119.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2016-5195.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2017-11882.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2018-20250.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/cve_rules/CVE-2018-4878.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/EMAIL_Cryptowall.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/Email_PHP_Mailer.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/Email_fake_it_maintenance_bulletin.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/Email_generic_phishing.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/Email_quota_limit_warning.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/attachment.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/email_Ukraine_BE_powerattack.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/extortion_email.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/image.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/scam.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/email/urls.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Angler.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Blackhole.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_BleedingLife.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Crimepack.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Eleonore.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Fragus.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Phoenix.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Sakura.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_ZeroAcces.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Zerox88.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/exploit_kits/EK_Zeus.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_APT10_MenuPass.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_APT19_CVE-2017-0199.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_APT_OLE_JSRat.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_CVE-2017-0199.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_CVE_2017_11882.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_CVE_2017_8759.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_Contains_VBE_File.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_DDE.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_Dridex.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_Hidden_PE_file.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_MIME_ActiveMime_b64.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_PDF.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_PowerPointMouse.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_Suspicious_OLE_target.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_UserForm.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_VBA_macro_code.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_Word_2007_XML_Flat_OPC.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_hancitor_dropper.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/Maldoc_malrtf_ole2link.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/maldocs/maldoc_somerules.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/packers/JJencode.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/packers/Javascript_exploit_and_obfuscation.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/packers/packer.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/packers/packer_compiler_signatures.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/packers/peid.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/packers/tweetable-polyglot-png.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/WShell_APT_Laudanum.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/WShell_ASPXSpy.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/WShell_ChinaChopper.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/WShell_Drupalgeddon2_icos.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/WShell_PHP_Anuna.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/WShell_PHP_in_images.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/WShell_THOR_Webshells.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/Wshell_ChineseSpam.yar"
include "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/webshells/Wshell_fire2013.yar"
