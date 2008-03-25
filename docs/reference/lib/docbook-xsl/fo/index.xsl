<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format"
                version='1.0'>

<!-- ********************************************************************
     $Id: index.xsl,v 1.1 2003/03/27 23:07:18 turin42 Exp $
     ********************************************************************

     This file is part of the XSL DocBook Stylesheet distribution.
     See ../README or http://nwalsh.com/docbook/xsl/ for copyright
     and other information.

     ******************************************************************** -->

<!-- ==================================================================== -->

<xsl:template match="index">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

 <xsl:if test="$generate.index != 0">
  <xsl:choose>
    <xsl:when test="$make.index.markup != 0">
      <fo:block>
        <xsl:call-template name="generate-index-markup">
          <xsl:with-param name="scope" select="(ancestor::book|/)[last()]"/>
        </xsl:call-template>
      </fo:block>
    </xsl:when>
    <xsl:otherwise>
      <fo:block id="{$id}">
        <xsl:call-template name="index.titlepage"/>
        <xsl:apply-templates/>
        <xsl:if test="count(indexentry) = 0 and count(indexdiv) = 0">
          <xsl:call-template name="generate-index">
            <xsl:with-param name="scope" select="(ancestor::book|/)[last()]"/>
          </xsl:call-template>
        </xsl:if>
      </fo:block>
    </xsl:otherwise>
  </xsl:choose>
 </xsl:if>
</xsl:template>

<xsl:template match="book/index|part/index">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

 <xsl:if test="$generate.index != 0">
  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster">
      <xsl:with-param name="pageclass">
        <xsl:if test="$make.index.markup != 0">body</xsl:if>
      </xsl:with-param>
    </xsl:call-template>
  </xsl:variable>

  <fo:page-sequence id="{$id}"
                    hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format"/>
    </xsl:attribute>
    <xsl:if test="$double.sided != 0">
      <xsl:attribute name="initial-page-number">auto-odd</xsl:attribute>
    </xsl:if>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>
    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="index.titlepage"/>
      <xsl:apply-templates/>
      <xsl:if test="count(indexentry) = 0 and count(indexdiv) = 0">

        <xsl:choose>
          <xsl:when test="$make.index.markup != 0">
            <fo:block wrap-option='no-wrap'
                      white-space-collapse='false'
                      xsl:use-attribute-sets="monospace.verbatim.properties"
                      linefeed-treatment="preserve">
              <xsl:call-template name="generate-index-markup">
                <xsl:with-param name="scope" select="(ancestor::book|/)[last()]"/>
              </xsl:call-template>
            </fo:block>
          </xsl:when>
          <xsl:when test="indexentry|indexdiv/indexentry">
            <xsl:apply-templates/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="generate-index">
              <xsl:with-param name="scope" select="(ancestor::book|/)[last()]"/>
            </xsl:call-template>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:if>
    </fo:flow>
  </fo:page-sequence>
 </xsl:if>
</xsl:template>

<xsl:template match="setindex">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

 <xsl:if test="$generate.index != 0">
  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster">
      <xsl:with-param name="pageclass">
        <xsl:choose>
          <xsl:when test="$make.index.markup != 0">body</xsl:when>
          <xsl:otherwise>index</xsl:otherwise>
        </xsl:choose>
      </xsl:with-param>
    </xsl:call-template>
  </xsl:variable>

  <fo:page-sequence id="{$id}"
                    hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format"/>
    </xsl:attribute>
    <xsl:if test="$double.sided != 0">
      <xsl:attribute name="initial-page-number">auto-odd</xsl:attribute>
    </xsl:if>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>
    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="setindex.titlepage"/>
      <xsl:apply-templates/>
      <xsl:if test="count(indexentry) = 0 and count(indexdiv) = 0">

        <xsl:choose>
          <xsl:when test="$make.index.markup != 0">
            <fo:block wrap-option='no-wrap'
                      white-space-collapse='false'
                      xsl:use-attribute-sets="monospace.verbatim.properties"
                      linefeed-treatment="preserve">
              <xsl:call-template name="generate-index-markup">
                <xsl:with-param name="scope" select="/"/>
              </xsl:call-template>
            </fo:block>
          </xsl:when>
          <xsl:when test="indexentry|indexdiv/indexentry">
            <xsl:apply-templates/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="generate-index">
              <xsl:with-param name="scope" select="/"/>
            </xsl:call-template>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:if>
    </fo:flow>
  </fo:page-sequence>
 </xsl:if>
</xsl:template>

<xsl:template match="index/title"></xsl:template>
<xsl:template match="index/subtitle"></xsl:template>
<xsl:template match="index/titleabbrev"></xsl:template>

<!-- ==================================================================== -->

<xsl:template name="indexdiv.title">
  <xsl:param name="title"/>
  <xsl:param name="titlecontent"/>

  <fo:block margin-left="{$title.margin.left}"
	    font-size="14.4pt"
            font-family="{$title.font.family}"
            font-weight="bold"
            keep-with-next.within-column="always"
            space-before.optimum="{$body.font.master}pt"
            space-before.minimum="{$body.font.master * 0.8}pt"
            space-before.maximum="{$body.font.master * 1.2}pt">
    <xsl:choose>
      <xsl:when test="$title">
        <xsl:apply-templates select="$title" mode="object.title.markup">
          <xsl:with-param name="allow-anchors" select="1"/>
        </xsl:apply-templates>
      </xsl:when>
      <xsl:otherwise>
        <xsl:copy-of select="$titlecontent"/>
      </xsl:otherwise>
    </xsl:choose>
  </fo:block>
</xsl:template>

<xsl:template match="indexdiv">
  <fo:block>
    <xsl:call-template name="indexdiv.titlepage"/>
    <xsl:apply-templates/>
  </fo:block>
</xsl:template>

<xsl:template match="indexdiv/title"/>
<xsl:template match="indexdiv/subtitle"/>
<xsl:template match="indexdiv/titleabbrev"/>

<!-- ==================================================================== -->

<xsl:template match="indexterm">
  <fo:wrapper>
    <xsl:attribute name="id">
      <xsl:call-template name="object.id"/>
    </xsl:attribute>
    <xsl:comment>
      <xsl:call-template name="comment-escape-string">
        <xsl:with-param name="string">
          <xsl:value-of select="primary"/>
          <xsl:if test="secondary">
            <xsl:text>, </xsl:text>
            <xsl:value-of select="secondary"/>
          </xsl:if>
          <xsl:if test="tertiary">
            <xsl:text>, </xsl:text>
            <xsl:value-of select="tertiary"/>
          </xsl:if>
        </xsl:with-param>
      </xsl:call-template>
    </xsl:comment>
  </fo:wrapper>
</xsl:template>

<!-- ==================================================================== -->

<xsl:template match="indexentry">
  <fo:block>
    <!-- don't process 'seeie's from here -->
    <xsl:apply-templates select="primaryie|secondaryie|tertiaryie|seealsoie"/>
  </fo:block>
</xsl:template>

<xsl:template match="primaryie">
  <fo:block>
    <xsl:apply-templates/>
    <xsl:if test="following-sibling::seeie">
      <xsl:text> (</xsl:text>
      <xsl:call-template name="gentext">
        <xsl:with-param name="key" select="'see'"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:apply-templates select="following-sibling::seeie"/>
      <xsl:text>)</xsl:text>
    </xsl:if>
  </fo:block>
</xsl:template>

<xsl:template match="secondaryie">
  <fo:block start-indent="1pc">
    <xsl:apply-templates/>
    <xsl:if test="following-sibling::seeie">
      <xsl:text> (</xsl:text>
      <xsl:call-template name="gentext">
        <xsl:with-param name="key" select="'see'"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:apply-templates select="following-sibling::seeie"/>
      <xsl:text>)</xsl:text>
    </xsl:if>
  </fo:block>
</xsl:template>

<xsl:template match="tertiaryie">
  <fo:block start-indent="2pc">
    <xsl:apply-templates/>
    <xsl:if test="following-sibling::seeie">
      <xsl:text> (</xsl:text>
      <xsl:call-template name="gentext">
        <xsl:with-param name="key" select="'see'"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:apply-templates select="following-sibling::seeie"/>
      <xsl:text>)</xsl:text>
    </xsl:if>
  </fo:block>
</xsl:template>

<xsl:template match="seeie">
  <fo:inline>
    <xsl:apply-templates/>
  </fo:inline>
</xsl:template>

<xsl:template match="seealsoie">
  <fo:block>
    <xsl:attribute name="start-indent">
      <xsl:choose>
        <xsl:when test="preceding-sibling::tertiaryie">3pc</xsl:when>
        <xsl:when test="preceding-sibling::secondaryie">2pc</xsl:when>
        <xsl:otherwise>1pc</xsl:otherwise>
      </xsl:choose>
    </xsl:attribute>
    <xsl:text>(</xsl:text>
    <xsl:call-template name="gentext">
      <xsl:with-param name="key" select="'seealso'"/>
    </xsl:call-template>
    <xsl:text> </xsl:text>
    <xsl:apply-templates/>
    <xsl:text>)</xsl:text>
  </fo:block>
</xsl:template>

</xsl:stylesheet>
