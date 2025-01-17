# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850624");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-12-13 05:53:58 +0100 (Sat, 13 Dec 2014)");
  script_cve_id("CVE-2014-0574", "CVE-2014-7899", "CVE-2014-7900", "CVE-2014-7901",
                "CVE-2014-7902", "CVE-2014-7903", "CVE-2014-7904", "CVE-2014-7905",
                "CVE-2014-7906", "CVE-2014-7907", "CVE-2014-7908", "CVE-2014-7909",
                "CVE-2014-7910");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2014:1626-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"chromium was updated to version 39.0.2171.65 to fix 13 security issues.

  These security issues were fixed:

  - Use-after-free in pepper plugins (CVE-2014-7906).

  - Buffer overflow in OpenJPEG before r2911 in PDFium, as used in Google
  Chromebefore 39.0.2171.65, al... (CVE-2014-7903).

  - Uninitialized memory read in Skia (CVE-2014-7909).

  - Unspecified security issues (CVE-2014-7910).

  - Integer overflow in media (CVE-2014-7908).

  - Integer overflow in the opj_t2_read_packet_data function
  infxcodec/fx_libopenjpeg/libopenjpeg20/t2.... (CVE-2014-7901).

  - Use-after-free in blink (CVE-2014-7907).

  - Address bar spoofing (CVE-2014-7899).

  - Buffer overflow in Skia (CVE-2014-7904).

  - Use-after-free vulnerability in the CPDF_Parser (CVE-2014-7900).

  - Use-after-free vulnerability in PDFium allows DoS (CVE-2014-7902).

  - Flaw allowing navigation to intents that do not have the BROWSABLE
  category (CVE-2014-7905).

  - Double-free in Flash (CVE-2014-0574).");

  script_tag(name:"affected", value:"chromium on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2014:1626-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~39.0.2171.65~58.4", rls:"openSUSE13.1"))) {
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
