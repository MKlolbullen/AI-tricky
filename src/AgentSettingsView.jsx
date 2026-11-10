import React from 'react';
import SavedAgentSettings from './SavedAgentSettings';
import ProviderModelSelector from './ModelSelector';
import TeamSettings from './TeamSettings';

export default function AgentSettingsView({index,onIndex,settings,onLoad,preset,onPreset,plannerModel,setPlannerModel,teamProps,runtime}){
 return <div className="assessment-grid"><div><SavedAgentSettings index={index} onIndex={onIndex} settings={settings} onLoad={onLoad} initialPreset={preset} onPreset={onPreset}/><h3>Planning model</h3><p>Shared by workflow planning, the canvas assistant and evidence follow-ups. Model reasoning is enabled separately for each request.</p><ProviderModelSelector runtime={runtime} value={plannerModel} onChange={setPlannerModel}/><h3>Team defaults</h3><TeamSettings {...teamProps} runtime={runtime}/></div><aside className="runtime-card"><h3>Your reusable setup</h3><p>Use named presets for different teams and model combinations. Loading applies the saved choices immediately; saving commits them to local SQLite storage.</p><p>The default is restored when a new workspace opens, including after restarting the platform. Existing runs and workflow node overrides retain their own settings.</p><p>Custom model IDs stay attached to their provider and become reusable dropdown entries when saved.</p></aside></div>;
}
