package zapclient

// AlertsFilter maps to ZAP's /JSON/core/view/alerts parameters.
type AlertsFilter struct {
	BaseURL     string
	URL         string
	RiskID      string // 0=Info,1=Low,2=Medium,3=High
	ContextName string
	Regex       bool
	Recurse     bool
	Start       int
	Count       int
}

// Alert is a tolerant mapping of ZAP alerts (numbers-as-strings safe).
type Alert struct {
	PluginID   string `json:"pluginId"`
	Alert      string `json:"alert"`
	Name       string `json:"name"`
	Risk       string `json:"risk"`
	RiskCode   string `json:"riskcode"`
	Confidence string `json:"confidence"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	Param      string `json:"param"`
	Attack     string `json:"attack"`
	Evidence   string `json:"evidence"`
	Other      string `json:"other"`
	Solution   string `json:"solution"`
	Reference  string `json:"reference"`
	CWEID      Intish `json:"cweid"`
	WASCID     Intish `json:"wascid"`
	SourceID   string `json:"sourceid"`
}

// Message models ZAP core/view/message response body.
// The API returns a single object with raw header strings and bodies.
type Message struct {
	RequestHeader  string `json:"requestHeader"`
	RequestBody    string `json:"requestBody"`
	ResponseHeader string `json:"responseHeader"`
	ResponseBody   string `json:"responseBody"`
}
