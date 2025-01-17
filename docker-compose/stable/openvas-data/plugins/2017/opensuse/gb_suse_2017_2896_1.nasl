# Copyright (C) 2017 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851636");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-10-30 09:24:40 +0100 (Mon, 30 Oct 2017)");
  script_cve_id("CVE-2015-1863", "CVE-2015-4141", "CVE-2015-4142", "CVE-2015-4143",
                "CVE-2015-4144", "CVE-2015-4145", "CVE-2015-5314", "CVE-2016-4476",
                "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081",
                "CVE-2017-13087", "CVE-2017-13088");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for hostapd (openSUSE-SU-2017:2896-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hostapd'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hostapd fixes the
  following issues:

  - Fix KRACK attacks on the AP side (boo#1063479, CVE-2017-13078,
  CVE-2017-13079, CVE-2017-13080, CVE-2017-13081, CVE-2017-13087,
  CVE-2017-13088):

  Hostap was updated to upstream release 2.6

  * fixed WPS configuration update vulnerability with malformed passphrase

  * extended channel switch support for VHT bandwidth changes

  * added support for configuring new ANQP-elements with
  anqp_elem= InfoID : hexdump of payload

  * fixed Suite B 192-bit AKM to use proper PMK length (note: this makes old
  releases incompatible with the fixed behavior)

  * added no_probe_resp_if_max_sta=1 parameter to disable Probe Response
  frame sending for not-associated STAs if max_num_sta limit has been
  reached

  * added option (-S as command line argument) to request all interfaces to
  be started at the same time

  * modified rts_threshold and fragm_threshold configuration parameters to
  allow -1 to be used to disable RTS/fragmentation

  * EAP-pwd: added support for Brainpool Elliptic Curves (with OpenSSL 1.0.2
  and newer)

  * fixed EAPOL reauthentication after FT protocol run

  * fixed FTIE generation for 4-way handshake after FT protocol run

  * fixed and improved various FST operations

  * TLS server

  - support SHA384 and SHA512 hashes

  - support TLS v1.2 signature algorithm with SHA384 and SHA512

  - support PKCS #5 v2.0 PBES2

  - support PKCS #5 with PKCS #12 style key decryption

  - minimal support for PKCS #12

  - support OCSP stapling (including ocsp_multi)

  * added support for OpenSSL 1.1 API changes

  - drop support for OpenSSL 0.9.8

  - drop support for OpenSSL 1.0.0

  * EAP-PEAP: support fast-connect crypto binding

  * RADIUS

  - fix Called-Station-Id to not escape SSID

  - add Event-Timestamp to all Accounting-Request packets

  - add Acct-Session-Id to Accounting-On/Off

  - add Acct-Multi-Session-Id  ton Access-Request packets

  - add Service-Type (= Frames)

  - allow server to provide PSK instead of passphrase for WPA-PSK
  Tunnel_password case

  - update full message for interim accounting updates

  - add Acct-Delay-Time into Accounting messages

  - add require_message_authenticator configuration option to require
  CoA/Disconnect-Request packets to be authenticated

  * started to postpone WNM-Notification frame sending by 100 ms so that the
  ST ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"hostapd on openSUSE Leap 42.3, openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:2896-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~2.6~5.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hostapd-debuginfo", rpm:"hostapd-debuginfo~2.6~5.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hostapd-debugsource", rpm:"hostapd-debugsource~2.6~5.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~2.6~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hostapd-debuginfo", rpm:"hostapd-debuginfo~2.6~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hostapd-debugsource", rpm:"hostapd-debugsource~2.6~8.1", rls:"openSUSELeap42.3"))) {
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
