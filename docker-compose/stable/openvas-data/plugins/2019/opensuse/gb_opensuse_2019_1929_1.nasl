# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852667");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2018-16858");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-08-19 02:00:46 +0000 (Mon, 19 Aug 2019)");
  script_name("openSUSE: Security Advisory for LibreOffice (openSUSE-SU-2019:1929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1929-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00059.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibreOffice'
  package(s) announced via the openSUSE-SU-2019:1929-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libreoffice and libraries fixes the following issues:

  LibreOffice was updated to 6.2.5.2 (fate#327121 bsc#1128845 bsc#1123455),
  bringing lots of bug and stability fixes.

  Additional bugfixes:

  - If there is no firebird engine we still need java to run hsqldb
  (bsc#1135189)

  - PPTX: Rectangle turns from green to blue and loses transparency when
  transparency is set (bsc#1135228)

  - Slide deck compression doesn't, hmm, compress too much (bsc#1127760)

  - Psychedelic graphics in LibreOffice (but not PowerPoint) (bsc#1124869)

  - Image from PPTX shown in a square, not a circle (bsc#1121874)

  libixion was updated to 0.14.1:

  * Updated for new orcus

  liborcus was updated to 0.14.1:

  * Boost 1.67 support

  * Various cell handling issues fixed

  libwps was updated to 0.4.10:

  * QuattroPro: add parser of .qwp files

  * all: support complex encoding

  mdds was updated to 1.4.3:

  * Api change to 1.4

  * More multivector operations and tweaks

  * Various multi vector fixes

  * flat_segment_tree: add segment iterator and functions

  * fix to handle out-of-range insertions on flat_segment_tree

  * Another api version -> rename to mdds-1_2

  myspell-dictionaries was updated to 20190423:

  * Serbian dictionary updated

  * Update af_ZA hunspell

  * Update Spanish dictionary

  * Update Slovenian dictionary

  * Update Breton dictionary

  * Update Galician dictionary

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1929=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1929=1");

  script_tag(name:"affected", value:"'LibreOffice' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"myspell-dictionaries", rpm:"myspell-dictionaries~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-en", rpm:"myspell-lightproof-en~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-hu_HU", rpm:"myspell-lightproof-hu_HU~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-pt_BR", rpm:"myspell-lightproof-pt_BR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-ru_RU", rpm:"myspell-lightproof-ru_RU~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-branding-upstream", rpm:"libreoffice-branding-upstream~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gdb-pretty-printers", rpm:"libreoffice-gdb-pretty-printers~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-glade", rpm:"libreoffice-glade~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-icon-themes", rpm:"libreoffice-icon-themes~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-af", rpm:"libreoffice-l10n-af~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-am", rpm:"libreoffice-l10n-am~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ar", rpm:"libreoffice-l10n-ar~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-as", rpm:"libreoffice-l10n-as~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ast", rpm:"libreoffice-l10n-ast~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-be", rpm:"libreoffice-l10n-be~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bg", rpm:"libreoffice-l10n-bg~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bn", rpm:"libreoffice-l10n-bn~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bn_IN", rpm:"libreoffice-l10n-bn_IN~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bo", rpm:"libreoffice-l10n-bo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-br", rpm:"libreoffice-l10n-br~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-brx", rpm:"libreoffice-l10n-brx~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bs", rpm:"libreoffice-l10n-bs~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ca", rpm:"libreoffice-l10n-ca~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ca_valencia", rpm:"libreoffice-l10n-ca_valencia~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-cs", rpm:"libreoffice-l10n-cs~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-cy", rpm:"libreoffice-l10n-cy~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-da", rpm:"libreoffice-l10n-da~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-de", rpm:"libreoffice-l10n-de~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dgo", rpm:"libreoffice-l10n-dgo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dsb", rpm:"libreoffice-l10n-dsb~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dz", rpm:"libreoffice-l10n-dz~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-el", rpm:"libreoffice-l10n-el~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en", rpm:"libreoffice-l10n-en~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en_GB", rpm:"libreoffice-l10n-en_GB~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en_ZA", rpm:"libreoffice-l10n-en_ZA~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-eo", rpm:"libreoffice-l10n-eo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-es", rpm:"libreoffice-l10n-es~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-et", rpm:"libreoffice-l10n-et~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-eu", rpm:"libreoffice-l10n-eu~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fa", rpm:"libreoffice-l10n-fa~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fi", rpm:"libreoffice-l10n-fi~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fr", rpm:"libreoffice-l10n-fr~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fy", rpm:"libreoffice-l10n-fy~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ga", rpm:"libreoffice-l10n-ga~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gd", rpm:"libreoffice-l10n-gd~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gl", rpm:"libreoffice-l10n-gl~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gu", rpm:"libreoffice-l10n-gu~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gug", rpm:"libreoffice-l10n-gug~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-he", rpm:"libreoffice-l10n-he~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hi", rpm:"libreoffice-l10n-hi~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hr", rpm:"libreoffice-l10n-hr~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hsb", rpm:"libreoffice-l10n-hsb~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hu", rpm:"libreoffice-l10n-hu~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-id", rpm:"libreoffice-l10n-id~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-is", rpm:"libreoffice-l10n-is~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-it", rpm:"libreoffice-l10n-it~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ja", rpm:"libreoffice-l10n-ja~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ka", rpm:"libreoffice-l10n-ka~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kab", rpm:"libreoffice-l10n-kab~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kk", rpm:"libreoffice-l10n-kk~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-km", rpm:"libreoffice-l10n-km~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kmr_Latn", rpm:"libreoffice-l10n-kmr_Latn~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kn", rpm:"libreoffice-l10n-kn~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ko", rpm:"libreoffice-l10n-ko~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kok", rpm:"libreoffice-l10n-kok~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ks", rpm:"libreoffice-l10n-ks~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lb", rpm:"libreoffice-l10n-lb~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lo", rpm:"libreoffice-l10n-lo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lt", rpm:"libreoffice-l10n-lt~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lv", rpm:"libreoffice-l10n-lv~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mai", rpm:"libreoffice-l10n-mai~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mk", rpm:"libreoffice-l10n-mk~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ml", rpm:"libreoffice-l10n-ml~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mn", rpm:"libreoffice-l10n-mn~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mni", rpm:"libreoffice-l10n-mni~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mr", rpm:"libreoffice-l10n-mr~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-my", rpm:"libreoffice-l10n-my~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nb", rpm:"libreoffice-l10n-nb~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ne", rpm:"libreoffice-l10n-ne~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nl", rpm:"libreoffice-l10n-nl~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nn", rpm:"libreoffice-l10n-nn~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nr", rpm:"libreoffice-l10n-nr~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nso", rpm:"libreoffice-l10n-nso~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-oc", rpm:"libreoffice-l10n-oc~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-om", rpm:"libreoffice-l10n-om~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-or", rpm:"libreoffice-l10n-or~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pa", rpm:"libreoffice-l10n-pa~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pl", rpm:"libreoffice-l10n-pl~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pt_BR", rpm:"libreoffice-l10n-pt_BR~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pt_PT", rpm:"libreoffice-l10n-pt_PT~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ro", rpm:"libreoffice-l10n-ro~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ru", rpm:"libreoffice-l10n-ru~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-rw", rpm:"libreoffice-l10n-rw~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sa_IN", rpm:"libreoffice-l10n-sa_IN~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sat", rpm:"libreoffice-l10n-sat~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sd", rpm:"libreoffice-l10n-sd~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-si", rpm:"libreoffice-l10n-si~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sid", rpm:"libreoffice-l10n-sid~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sk", rpm:"libreoffice-l10n-sk~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sl", rpm:"libreoffice-l10n-sl~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sq", rpm:"libreoffice-l10n-sq~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sr", rpm:"libreoffice-l10n-sr~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ss", rpm:"libreoffice-l10n-ss~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-st", rpm:"libreoffice-l10n-st~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sv", rpm:"libreoffice-l10n-sv~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sw_TZ", rpm:"libreoffice-l10n-sw_TZ~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ta", rpm:"libreoffice-l10n-ta~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-te", rpm:"libreoffice-l10n-te~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tg", rpm:"libreoffice-l10n-tg~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-th", rpm:"libreoffice-l10n-th~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tn", rpm:"libreoffice-l10n-tn~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tr", rpm:"libreoffice-l10n-tr~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ts", rpm:"libreoffice-l10n-ts~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tt", rpm:"libreoffice-l10n-tt~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ug", rpm:"libreoffice-l10n-ug~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-uk", rpm:"libreoffice-l10n-uk~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-uz", rpm:"libreoffice-l10n-uz~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ve", rpm:"libreoffice-l10n-ve~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-vec", rpm:"libreoffice-l10n-vec~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-vi", rpm:"libreoffice-l10n-vi~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-xh", rpm:"libreoffice-l10n-xh~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zh_CN", rpm:"libreoffice-l10n-zh_CN~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zh_TW", rpm:"libreoffice-l10n-zh_TW~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zu", rpm:"libreoffice-l10n-zu~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mdds-1_4-devel", rpm:"mdds-1_4-devel~1.4.3~lp150.2.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-af_NA", rpm:"myspell-af_NA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-af_ZA", rpm:"myspell-af_ZA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-an", rpm:"myspell-an~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-an_ES", rpm:"myspell-an_ES~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar", rpm:"myspell-ar~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_AE", rpm:"myspell-ar_AE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_BH", rpm:"myspell-ar_BH~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_DZ", rpm:"myspell-ar_DZ~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_EG", rpm:"myspell-ar_EG~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_IQ", rpm:"myspell-ar_IQ~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_JO", rpm:"myspell-ar_JO~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_KW", rpm:"myspell-ar_KW~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_LB", rpm:"myspell-ar_LB~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_LY", rpm:"myspell-ar_LY~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_MA", rpm:"myspell-ar_MA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_OM", rpm:"myspell-ar_OM~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_QA", rpm:"myspell-ar_QA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_SA", rpm:"myspell-ar_SA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_SD", rpm:"myspell-ar_SD~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_SY", rpm:"myspell-ar_SY~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_TN", rpm:"myspell-ar_TN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ar_YE", rpm:"myspell-ar_YE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-be_BY", rpm:"myspell-be_BY~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-bg_BG", rpm:"myspell-bg_BG~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-bn_BD", rpm:"myspell-bn_BD~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-bn_IN", rpm:"myspell-bn_IN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-bo", rpm:"myspell-bo~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-bo_CN", rpm:"myspell-bo_CN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-bo_IN", rpm:"myspell-bo_IN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-br_FR", rpm:"myspell-br_FR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-bs", rpm:"myspell-bs~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-bs_BA", rpm:"myspell-bs_BA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ca", rpm:"myspell-ca~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ca_AD", rpm:"myspell-ca_AD~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ca_ES", rpm:"myspell-ca_ES~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ca_ES_valencia", rpm:"myspell-ca_ES_valencia~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ca_FR", rpm:"myspell-ca_FR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ca_IT", rpm:"myspell-ca_IT~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-cs_CZ", rpm:"myspell-cs_CZ~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-da_DK", rpm:"myspell-da_DK~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-de", rpm:"myspell-de~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-de_AT", rpm:"myspell-de_AT~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-de_CH", rpm:"myspell-de_CH~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-de_DE", rpm:"myspell-de_DE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-el_GR", rpm:"myspell-el_GR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en", rpm:"myspell-en~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_AU", rpm:"myspell-en_AU~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_BS", rpm:"myspell-en_BS~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_BZ", rpm:"myspell-en_BZ~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_CA", rpm:"myspell-en_CA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_GB", rpm:"myspell-en_GB~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_GH", rpm:"myspell-en_GH~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_IE", rpm:"myspell-en_IE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_IN", rpm:"myspell-en_IN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_JM", rpm:"myspell-en_JM~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_MW", rpm:"myspell-en_MW~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_NA", rpm:"myspell-en_NA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_NZ", rpm:"myspell-en_NZ~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_PH", rpm:"myspell-en_PH~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_TT", rpm:"myspell-en_TT~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_US", rpm:"myspell-en_US~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_ZA", rpm:"myspell-en_ZA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_ZW", rpm:"myspell-en_ZW~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es", rpm:"myspell-es~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_AR", rpm:"myspell-es_AR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_BO", rpm:"myspell-es_BO~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_CL", rpm:"myspell-es_CL~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_CO", rpm:"myspell-es_CO~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_CR", rpm:"myspell-es_CR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_CU", rpm:"myspell-es_CU~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_DO", rpm:"myspell-es_DO~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_EC", rpm:"myspell-es_EC~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_ES", rpm:"myspell-es_ES~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_GT", rpm:"myspell-es_GT~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_HN", rpm:"myspell-es_HN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_MX", rpm:"myspell-es_MX~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_NI", rpm:"myspell-es_NI~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_PA", rpm:"myspell-es_PA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_PE", rpm:"myspell-es_PE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_PR", rpm:"myspell-es_PR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_PY", rpm:"myspell-es_PY~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_SV", rpm:"myspell-es_SV~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_UY", rpm:"myspell-es_UY~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_VE", rpm:"myspell-es_VE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-et_EE", rpm:"myspell-et_EE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-fr_BE", rpm:"myspell-fr_BE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-fr_CA", rpm:"myspell-fr_CA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-fr_CH", rpm:"myspell-fr_CH~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-fr_FR", rpm:"myspell-fr_FR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-fr_LU", rpm:"myspell-fr_LU~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-fr_MC", rpm:"myspell-fr_MC~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-gd_GB", rpm:"myspell-gd_GB~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-gl", rpm:"myspell-gl~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-gl_ES", rpm:"myspell-gl_ES~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-gu_IN", rpm:"myspell-gu_IN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-gug", rpm:"myspell-gug~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-gug_PY", rpm:"myspell-gug_PY~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-he_IL", rpm:"myspell-he_IL~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-hi_IN", rpm:"myspell-hi_IN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-hr_HR", rpm:"myspell-hr_HR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-hu_HU", rpm:"myspell-hu_HU~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-id", rpm:"myspell-id~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-id_ID", rpm:"myspell-id_ID~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-is", rpm:"myspell-is~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-is_IS", rpm:"myspell-is_IS~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-it_IT", rpm:"myspell-it_IT~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-kmr_Latn", rpm:"myspell-kmr_Latn~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-kmr_Latn_SY", rpm:"myspell-kmr_Latn_SY~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-kmr_Latn_TR", rpm:"myspell-kmr_Latn_TR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lo_LA", rpm:"myspell-lo_LA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lt_LT", rpm:"myspell-lt_LT~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lv_LV", rpm:"myspell-lv_LV~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-nb_NO", rpm:"myspell-nb_NO~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ne_NP", rpm:"myspell-ne_NP~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-nl_BE", rpm:"myspell-nl_BE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-nl_NL", rpm:"myspell-nl_NL~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-nn_NO", rpm:"myspell-nn_NO~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-no", rpm:"myspell-no~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-oc_FR", rpm:"myspell-oc_FR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-pl_PL", rpm:"myspell-pl_PL~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-pt_AO", rpm:"myspell-pt_AO~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-pt_BR", rpm:"myspell-pt_BR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-pt_PT", rpm:"myspell-pt_PT~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ro", rpm:"myspell-ro~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ro_RO", rpm:"myspell-ro_RO~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ru_RU", rpm:"myspell-ru_RU~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-si_LK", rpm:"myspell-si_LK~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sk_SK", rpm:"myspell-sk_SK~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sl_SI", rpm:"myspell-sl_SI~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sq_AL", rpm:"myspell-sq_AL~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sr", rpm:"myspell-sr~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sr_CS", rpm:"myspell-sr_CS~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sr_Latn_CS", rpm:"myspell-sr_Latn_CS~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sr_Latn_RS", rpm:"myspell-sr_Latn_RS~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sr_RS", rpm:"myspell-sr_RS~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sv_FI", rpm:"myspell-sv_FI~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sv_SE", rpm:"myspell-sv_SE~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-sw_TZ", rpm:"myspell-sw_TZ~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-te", rpm:"myspell-te~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-te_IN", rpm:"myspell-te_IN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-th_TH", rpm:"myspell-th_TH~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-tr", rpm:"myspell-tr~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-tr_TR", rpm:"myspell-tr_TR~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-uk_UA", rpm:"myspell-uk_UA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-vi", rpm:"myspell-vi~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-vi_VN", rpm:"myspell-vi_VN~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-zu_ZA", rpm:"myspell-zu_ZA~20190423~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libixion-0_14-0", rpm:"libixion-0_14-0~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libixion-0_14-0-debuginfo", rpm:"libixion-0_14-0-debuginfo~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libixion-debuginfo", rpm:"libixion-debuginfo~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libixion-debugsource", rpm:"libixion-debugsource~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libixion-devel", rpm:"libixion-devel~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libixion-tools", rpm:"libixion-tools~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libixion-tools-debuginfo", rpm:"libixion-tools-debuginfo~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborcus-0_14-0", rpm:"liborcus-0_14-0~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborcus-0_14-0-debuginfo", rpm:"liborcus-0_14-0-debuginfo~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborcus-debuginfo", rpm:"liborcus-debuginfo~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborcus-debugsource", rpm:"liborcus-debugsource~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborcus-devel", rpm:"liborcus-devel~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborcus-tools", rpm:"liborcus-tools~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborcus-tools-debuginfo", rpm:"liborcus-tools-debuginfo~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice", rpm:"libreoffice~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base", rpm:"libreoffice-base~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-debuginfo", rpm:"libreoffice-base-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-drivers-firebird", rpm:"libreoffice-base-drivers-firebird~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-drivers-firebird-debuginfo", rpm:"libreoffice-base-drivers-firebird-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-drivers-postgresql", rpm:"libreoffice-base-drivers-postgresql~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-drivers-postgresql-debuginfo", rpm:"libreoffice-base-drivers-postgresql-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc", rpm:"libreoffice-calc~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc-debuginfo", rpm:"libreoffice-calc-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc-extensions", rpm:"libreoffice-calc-extensions~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-debuginfo", rpm:"libreoffice-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-debugsource", rpm:"libreoffice-debugsource~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-draw", rpm:"libreoffice-draw~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-draw-debuginfo", rpm:"libreoffice-draw-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-filters-optional", rpm:"libreoffice-filters-optional~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gnome", rpm:"libreoffice-gnome~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gnome-debuginfo", rpm:"libreoffice-gnome-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk2", rpm:"libreoffice-gtk2~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk2-debuginfo", rpm:"libreoffice-gtk2-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3", rpm:"libreoffice-gtk3~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3-debuginfo", rpm:"libreoffice-gtk3-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-impress", rpm:"libreoffice-impress~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-impress-debuginfo", rpm:"libreoffice-impress-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-mailmerge", rpm:"libreoffice-mailmerge~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-math", rpm:"libreoffice-math~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-math-debuginfo", rpm:"libreoffice-math-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean", rpm:"libreoffice-officebean~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean-debuginfo", rpm:"libreoffice-officebean-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pyuno", rpm:"libreoffice-pyuno~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pyuno-debuginfo", rpm:"libreoffice-pyuno-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-qt5", rpm:"libreoffice-qt5~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-qt5-debuginfo", rpm:"libreoffice-qt5-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk", rpm:"libreoffice-sdk~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk-debuginfo", rpm:"libreoffice-sdk-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk-doc", rpm:"libreoffice-sdk-doc~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer", rpm:"libreoffice-writer~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer-debuginfo", rpm:"libreoffice-writer-debuginfo~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer-extensions", rpm:"libreoffice-writer-extensions~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit", rpm:"libreofficekit~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit-devel", rpm:"libreofficekit-devel~6.2.5.2~lp150.2.13.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwps-0_4-4", rpm:"libwps-0_4-4~0.4.10~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwps-0_4-4-debuginfo", rpm:"libwps-0_4-4-debuginfo~0.4.10~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwps-debuginfo", rpm:"libwps-debuginfo~0.4.10~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwps-debugsource", rpm:"libwps-debugsource~0.4.10~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwps-devel", rpm:"libwps-devel~0.4.10~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwps-tools", rpm:"libwps-tools~0.4.10~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwps-tools-debuginfo", rpm:"libwps-tools-debuginfo~0.4.10~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libixion", rpm:"python3-libixion~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libixion-debuginfo", rpm:"python3-libixion-debuginfo~0.14.1~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-liborcus", rpm:"python3-liborcus~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-liborcus-debuginfo", rpm:"python3-liborcus-debuginfo~0.14.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
