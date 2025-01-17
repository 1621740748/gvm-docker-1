# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0221.1");
  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-28 13:12:00 +0000 (Fri, 28 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0221-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0221-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120221-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2012:0221-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to 3.6.26 fixing bugs and security issues.

The following security issues have been fixed by this update:

 *

 MFSA 2012-01: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 In general these flaws cannot be exploited through email in the Thunderbird and SeaMonkey products because scripting is disabled, but are potentially a risk in browser or browser-like contexts in those products.
References

 *

 CVE-2012-0442: Jesse Ruderman and Bob Clary reported memory safety problems that were fixed in both Firefox 10 and Firefox 3.6.26.

 *

 MFSA 2012-02/CVE-2011-3670: For historical reasons Firefox has been generous in its interpretation of web addresses containing square brackets around the host. If this host was not a valid IPv6 literal address, Firefox attempted to interpret the host as a regular domain name.
Gregory Fleischer reported that requests made using IPv6 syntax using XMLHttpRequest objects through a proxy may generate errors depending on proxy configuration for IPv6.
The resulting error messages from the proxy may disclose sensitive data because Same-Origin Policy (SOP) will allow the XMLHttpRequest object to read these error messages,
allowing user privacy to be eroded. Firefox now enforces RFC 3986 IPv6 literal syntax and that may break links written using the non-standard Firefox-only forms that were previously accepted.

 This was fixed previously for Firefox 7.0,
Thunderbird 7.0, and SeaMonkey 2.4 but only fixed in Firefox 3.6.26 and Thunderbird 3.1.18 during 2012.

 *

 MFSA 2012-04/CVE-2011-3659: Security researcher regenrecht reported via TippingPoint's Zero Day Initiative that removed child nodes of nsDOMAttribute can be accessed under certain circumstances because of a premature notification of AttributeChildRemoved. This use-after-free of the child nodes could possibly allow for for remote code execution.

 *

 MFSA 2012-07/CVE-2012-0444: Security researcher regenrecht reported via TippingPoint's Zero Day Initiative the possibility of memory corruption during the decoding of Ogg Vorbis files. This can cause a crash during decoding and has the potential for remote code execution.

 *

 MFSA 2012-08/CVE-2012-0449: Security researchers Nicolas Gregoire and Aki Helin independently reported that when processing a malformed embedded XSLT stylesheet,
Firefox can crash due to a memory corruption. While there is no evidence that this is directly exploitable, there is a possibility of remote code execution.");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SLE SDK 10 SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192", rpm:"mozilla-xulrunner192~1.9.2.26~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome", rpm:"mozilla-xulrunner192-gnome~1.9.2.26~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations", rpm:"mozilla-xulrunner192-translations~1.9.2.26~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.6.26~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.6.26~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-32bit", rpm:"mozilla-xulrunner192-32bit~1.9.2.26~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome-32bit", rpm:"mozilla-xulrunner192-gnome-32bit~1.9.2.26~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-32bit", rpm:"mozilla-xulrunner192-translations-32bit~1.9.2.26~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
