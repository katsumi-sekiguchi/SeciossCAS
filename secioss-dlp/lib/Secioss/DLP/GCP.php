<?php
/**
 *  GCP.php
 *
 *  PHP versions 5
 *
 *  @package    GCP
 *  @author     Kaoru Sekiguchi <sekiguchi.kaoru@secioss.co.jp>
 *  @copyright  2018 SECIOSS, INC.
 *  @version    CVS: $Id$
 */

namespace Secioss\DLP;

require_once('Secioss/DLP/DLP.php');

use Google\Cloud\Dlp\V2\DlpServiceClient;
use Google\Cloud\Dlp\V2\ContentItem;
use Google\Cloud\Dlp\V2\InfoType;
use Google\Cloud\Dlp\V2\InspectConfig;
use Google\Cloud\Dlp\V2\Likelihood;
use Google\Cloud\Dlp\V2\InspectConfig_FindingLimits;
use Google\Cloud\Dlp\V2\ByteContentItem;
use Google\Cloud\Dlp\V2\CustomInfoType;
use Google\Cloud\Dlp\V2\StoredType;

/**
 *  GCP
 *
 *  @package    DLP
 *  @author     Kaoru Sekiguchi <sekiguchi.kaoru@secioss.co.jp>
 *  @copyright  2018 SECIOSS, INC.
 *  @version    CVS: $Id$
 */
class GCP extends DLP
{
    protected $client;

    protected $inspectConfig;

    protected $parent;

    // {{{ DLP_GCP
    /**
     *  DLP_GCPクラスのコンストラクタ
     *
     *  @access public
     *  @param  mixed   $options        GCPの設定
     *  @return mixed   0:正常終了 PEAR_Error:エラー
     */
    function __construct(array $config)
    {
        putenv('GOOGLE_APPLICATION_CREDENTIALS='.$config['credentials']);

        $maxFindings = 0;

        $this->client = new DlpServiceClient();

        // The infoTypes of information to match
//        $ageInfoType = (new InfoType())->setName('AGE');
        $cardNumberInfoType = (new InfoType())->setName('CREDIT_CARD_NUMBER');
        $emailInfoType = (new InfoType())->setName('EMAIL_ADDRESS');
        $locationInfoType = (new InfoType())->setName('LOCATION');
        $phoneNumberInfoType = (new InfoType())->setName('PHONE_NUMBER');
        $individualNumberInfoType = (new InfoType())->setName('JAPAN_INDIVIDUAL_NUMBER');
        $infoTypes = [$cardNumberInfoType, $emailInfoType, $locationInfoType, $phoneNumberInfoType, $individualNumberInfoType];

        $customInfoTypes = array();
        if (isset($config['person_dictionary'])) {
            $japanPersonNameInfoType = (new CustomInfoType())->setInfoType((new InfoType())->setName('JAPAN_PERSON_NAME'))->setStoredType((new StoredType())->setName('projects/'.$config['projectid'].'/storedInfoTypes/'.$config['person_dictionary']));
            $customInfoTypes[] = $japanPersonNameInfoType;
        }

        // The minimum likelihood required before returning a match
        $minLikelihood = likelihood::LIKELIHOOD_UNSPECIFIED;

        // Whether to include the matching string in the response
        $includeQuote = true;

        // Specify finding limits
        $limits = (new InspectConfig_FindingLimits())
            ->setMaxFindingsPerRequest($maxFindings);

        // Create the configuration object
        $this->inspectConfig = (new InspectConfig())
            ->setMinLikelihood($minLikelihood)
            ->setLimits($limits)
            ->setInfoTypes($infoTypes)
            ->setIncludeQuote($includeQuote);
        if (count($customInfoTypes)) {
            $this->inspectConfig->setCustomInfoTypes($customInfoTypes);
        }

        $this->parent = $this->client->projectName($config['projectid']);
    }
    // }}}

    function inspect($data)
    {
        $likelihoods = ['Unknown', 'Very unlikely', 'Unlikely', 'Possible', 'Likely', 'Very likely'];

        $content = (new ContentItem())
            ->setValue($data);

        // Run request
        $response = $this->client->inspectContent($this->parent, [
            'inspectConfig' => $this->inspectConfig,
            'item' => $content
        ]);

        $messages = array();
        $findings = $response->getResult()->getFindings();
        if (count($findings) != 0) {
            foreach ($findings as $finding) {
                $message = 'Quote: ' . $finding->getQuote() . ' ';
                $message .= ' Info type: ' . $finding->getInfoType()->getName() . ' ';
                $likelihoodString = $likelihoods[$finding->getLikelihood()];
                $message .= ' Likelihood: ' . $likelihoodString;
                $messages[] = $message;
            }
        }

        return $messages;
    }
}

?>
