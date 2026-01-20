import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, 
  Wifi, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  RefreshCw, 
  Plus, 
  Trash2,
  Settings,
  Activity,
  Clock,
  Signal,
  Lock,
  Eye,
  EyeOff
} from 'lucide-react';

const API_BASE_URL = ''; 


const api = {
  getStatus: async () => {
    const response = await fetch(`${API_BASE_URL}/status`);
    return response.json();
  },
  getNetworks: async () => {
    const response = await fetch(`${API_BASE_URL}/networks`);
    return response.json();
  },
  getSuspiciousNetworks: async () => {
    const response = await fetch(`${API_BASE_URL}/networks/suspicious`);
    return response.json();
  },
  getAlerts: async (limit = 100) => {
    const response = await fetch(`${API_BASE_URL}/alerts?limit=${limit}`);
    return response.json();
  },
  getWhitelist: async () => {
    const response = await fetch(`${API_BASE_URL}/whitelist`);
    return response.json();
  },
  addToWhitelist: async (ssid, bssids) => {
    const response = await fetch(`${API_BASE_URL}/whitelist/${encodeURIComponent(ssid)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bssids),
    });
    return response.json();
  },
  removeFromWhitelist: async (ssid) => {
    const response = await fetch(`${API_BASE_URL}/whitelist/${encodeURIComponent(ssid)}`, {
      method: 'DELETE',
    });
    return response.json();
  },
  removeBSSIDFromWhitelist: async (ssid, bssid) => {
    const response = await fetch(`${API_BASE_URL}/whitelist/${encodeURIComponent(ssid)}/${encodeURIComponent(bssid)}`, {
      method: 'DELETE',
    });
    return response.json();
  },
  clearAlerts: async () => {
    const response = await fetch(`${API_BASE_URL}/alerts`, {
      method: 'DELETE',
    });
    return response.json();
  },
};


const StatusCard = ({ status, onRefresh }) => {
  const formatUptime = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
          <Activity className="w-6 h-6" />
          System Status
        </h2>
        <button
          onClick={onRefresh}
          className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
        >
          <RefreshCw className="w-5 h-5" />
        </button>
      </div>
      
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="text-center">
          <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
            status?.is_running ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
          }`}>
            {status?.is_running ? <CheckCircle className="w-4 h-4 mr-1" /> : <XCircle className="w-4 h-4 mr-1" />}
            {status?.is_running ? 'Running' : 'Stopped'}
          </div>
          <p className="text-gray-600 text-sm mt-1">Monitor Status</p>
        </div>
        
        <div className="text-center">
          <div className="text-2xl font-bold text-gray-800">{status?.scan_count || 0}</div>
          <p className="text-gray-600 text-sm">Total Scans</p>
        </div>
        
        <div className="text-center">
          <div className="text-2xl font-bold text-blue-600">{status?.total_networks || 0}</div>
          <p className="text-gray-600 text-sm">Networks Found</p>
        </div>
        
        <div className="text-center">
          <div className="text-2xl font-bold text-red-600">{status?.suspicious_networks || 0}</div>
          <p className="text-gray-600 text-sm">Suspicious</p>
        </div>
      </div>
      
      <div className="mt-4 pt-4 border-t">
        <div className="flex items-center justify-between text-sm text-gray-600">
          <span className="flex items-center gap-1">
            <Clock className="w-4 h-4" />
            Last Scan: {status?.last_scan_time || 'Never'}
          </span>
          <span>Uptime: {status ? formatUptime(status.uptime_seconds) : '0h 0m'}</span>
        </div>
      </div>
    </div>
  );
};


const NetworkList = ({ networks, onAddToWhitelist, showOnlySuspicious = false }) => {
  const [sortBy, setSortBy] = useState('ssid');
  const [sortOrder, setSortOrder] = useState('asc');

  const filteredNetworks = showOnlySuspicious ? networks.filter(n => n.is_suspicious) : networks;

  const sortedNetworks = [...filteredNetworks].sort((a, b) => {
    let aVal = a[sortBy];
    let bVal = b[sortBy];
    
    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase();
      bVal = bVal.toLowerCase();
    }
    
    if (sortOrder === 'asc') {
      return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
    } else {
      return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
    }
  });

  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('asc');
    }
  };

  const getSignalStrength = (rssi) => {
    if (rssi === null || rssi === undefined) return 'Unknown';
    if (rssi > -50) return 'Excellent';
    if (rssi > -60) return 'Good';
    if (rssi > -70) return 'Fair';
    return 'Poor';
  };

  const getSecurityDisplay = (security) => {
    if (!security || security === '--') return 'Open';
    return security;
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
          <Wifi className="w-6 h-6" />
          {showOnlySuspicious ? 'Suspicious Networks' : 'All Networks'} ({filteredNetworks.length})
        </h2>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b">
              <th 
                className="text-left p-3 cursor-pointer hover:bg-gray-50"
                onClick={() => handleSort('ssid')}
              >
                SSID {sortBy === 'ssid' && (sortOrder === 'asc' ? '↑' : '↓')}
              </th>
              <th 
                className="text-left p-3 cursor-pointer hover:bg-gray-50"
                onClick={() => handleSort('bssid')}
              >
                BSSID {sortBy === 'bssid' && (sortOrder === 'asc' ? '↑' : '↓')}
              </th>
              <th 
                className="text-left p-3 cursor-pointer hover:bg-gray-50"
                onClick={() => handleSort('vendor')}
              >
                Vendor {sortBy === 'vendor' && (sortOrder === 'asc' ? '↑' : '↓')}
              </th>
              <th 
                className="text-left p-3 cursor-pointer hover:bg-gray-50"
                onClick={() => handleSort('rssi')}
              >
                Signal {sortBy === 'rssi' && (sortOrder === 'asc' ? '↑' : '↓')}
              </th>
              <th 
                className="text-left p-3 cursor-pointer hover:bg-gray-50"
                onClick={() => handleSort('security')}
              >
                Security {sortBy === 'security' && (sortOrder === 'asc' ? '↑' : '↓')}
              </th>
              <th className="text-left p-3">Status</th>
              <th className="text-left p-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {sortedNetworks.map((network, index) => (
              <tr key={`${network.ssid}-${network.bssid}`} className="border-b hover:bg-gray-50">
                <td className="p-3 font-medium">{network.ssid}</td>
                <td className="p-3 font-mono text-xs">{network.bssid}</td>
                <td className="p-3">{network.vendor}</td>
                <td className="p-3">
                  <div className="flex items-center gap-1">
                    <Signal className="w-4 h-4" />
                    {network.rssi ? `${network.rssi} dBm` : 'N/A'}
                    <span className="text-xs text-gray-500">
                      ({getSignalStrength(network.rssi)})
                    </span>
                  </div>
                </td>
                <td className="p-3">
                  <div className="flex items-center gap-1">
                    <Lock className="w-4 h-4" />
                    {getSecurityDisplay(network.security)}
                  </div>
                </td>
                <td className="p-3">
                  <div className="flex flex-col gap-1">
                    {network.is_whitelisted && (
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        <CheckCircle className="w-3 h-3 mr-1" />
                        Trusted
                      </span>
                    )}
                    {network.is_honeypot && (
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                        <AlertTriangle className="w-3 h-3 mr-1" />
                        Honeypot
                      </span>
                    )}
                    {network.is_suspicious && !network.is_honeypot && (
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                        <AlertTriangle className="w-3 h-3 mr-1" />
                        Suspicious
                      </span>
                    )}
                  </div>
                </td>
                <td className="p-3">
                  {!network.is_whitelisted && (
                    <button
                      onClick={() => onAddToWhitelist(network.ssid, network.bssid)}
                      className="inline-flex items-center px-2 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700 transition-colors"
                    >
                      <Plus className="w-3 h-3 mr-1" />
                      Trust
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};


const WhitelistManager = ({ whitelist, onUpdate, onDelete, onDeleteBSSID }) => {
  const [newSSID, setNewSSID] = useState('');
  const [newBSSID, setNewBSSID] = useState('');
  const [expandedSSIDs, setExpandedSSIDs] = useState(new Set());

  const toggleExpanded = (ssid) => {
    const newExpanded = new Set(expandedSSIDs);
    if (newExpanded.has(ssid)) {
      newExpanded.delete(ssid);
    } else {
      newExpanded.add(ssid);
    }
    setExpandedSSIDs(newExpanded);
  };

  const handleAddEntry = async () => {
    if (newSSID.trim() && newBSSID.trim()) {
      try {
        await onUpdate(newSSID.trim(), [newBSSID.trim()]);
        setNewSSID('');
        setNewBSSID('');
      } catch (error) {
        alert('Failed to add whitelist entry: ' + error.message);
      }
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
          <Shield className="w-6 h-6" />
          Whitelist Management
        </h2>
      </div>

      {/* Add new entry */}
      <div className="mb-6 p-4 bg-gray-50 rounded-lg">
        <h3 className="text-lg font-medium mb-3">Add New Trusted Network</h3>
        <div className="flex gap-3">
          <input
            type="text"
            placeholder="SSID (e.g., HomeWiFi)"
            value={newSSID}
            onChange={(e) => setNewSSID(e.target.value)}
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <input
            type="text"
            placeholder="BSSID (e.g., 00:11:22:33:44:55)"
            value={newBSSID}
            onChange={(e) => setNewBSSID(e.target.value)}
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            onClick={handleAddEntry}
            className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add
          </button>
        </div>
      </div>

      {/* Existing whitelist */}
      <div className="space-y-3">
        {Object.entries(whitelist).map(([ssid, bssids]) => (
          <div key={ssid} className="border border-gray-200 rounded-lg">
            <div 
              className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50"
              onClick={() => toggleExpanded(ssid)}
            >
              <div className="flex items-center gap-3">
                {expandedSSIDs.has(ssid) ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                <span className="font-medium">{ssid}</span>
                <span className="text-sm text-gray-500">({bssids.length} BSSID{bssids.length !== 1 ? 's' : ''})</span>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  
                  if (confirm(`Remove ${ssid} from whitelist?`)) {
                    onDelete(ssid);
                  }
                }}
                className="p-1 text-red-600 hover:bg-red-50 rounded"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
            
            {expandedSSIDs.has(ssid) && (
              <div className="px-4 pb-4">
                <div className="space-y-2">
                  {bssids.map((bssid, index) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                      <span className="font-mono text-sm">{bssid}</span>
                      <button
                        onClick={() => {
                          
                          if (confirm(`Remove BSSID ${bssid} from ${ssid}?`)) {
                            onDeleteBSSID(ssid, bssid);
                          }
                        }}
                        className="p-1 text-red-600 hover:bg-red-100 rounded"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};


const AlertsPanel = ({ alerts, onClearAlerts }) => {
  const getAlertColor = (alertType) => {
    switch (alertType) {
      case 'honeypot': return 'bg-red-100 text-red-800 border-red-200';
      case 'rogue': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'untrusted': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
          <AlertTriangle className="w-6 h-6" />
          Recent Alerts ({alerts.length})
        </h2>
        {alerts.length > 0 && (
          <button
            onClick={onClearAlerts}
            className="px-3 py-1 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
          >
            Clear All
          </button>
        )}
      </div>

      <div className="space-y-3 max-h-96 overflow-y-auto">
        {alerts.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
            No recent alerts
          </div>
        ) : (
          alerts.slice().reverse().map((alert, index) => (
            <div 
              key={index}
              className={`p-4 rounded-lg border ${getAlertColor(alert.alert_type)}`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium">{alert.ssid}</span>
                <span className="text-xs opacity-75">{alert.timestamp}</span>
              </div>
              <div className="text-sm space-y-1">
                <div>BSSID: <span className="font-mono">{alert.bssid}</span></div>
                <div>Vendor: {alert.vendor}</div>
                {alert.rssi && <div>Signal: {alert.rssi} dBm</div>}
                {alert.channel && <div>Channel: {alert.channel}</div>}
                <div>Type: <span className="font-medium capitalize">{alert.alert_type}</span></div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};


const WiFiMonitorDashboard = () => {
  const [status, setStatus] = useState(null);
  const [networks, setNetworks] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [whitelist, setWhitelist] = useState({});
  const [activeTab, setActiveTab] = useState('dashboard');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [statusData, networksData, alertsData, whitelistData] = await Promise.all([
        api.getStatus(),
        api.getNetworks(),
        api.getAlerts(50),
        api.getWhitelist(),
      ]);
      
      setStatus(statusData);
      setNetworks(networksData);
      setAlerts(alertsData);
      setWhitelist(whitelistData);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); 
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleAddToWhitelist = async (ssid, bssid) => {
    try {
      await api.addToWhitelist(ssid, [bssid]);
      await fetchData(); 
    } catch (err) {
      alert('Failed to add to whitelist: ' + err.message);
    }
  };

  const handleUpdateWhitelist = async (ssid, bssids) => {
    try {
      await api.addToWhitelist(ssid, bssids);
      await fetchData(); 
    } catch (err) {
      throw err;
    }
  };

  const handleDeleteFromWhitelist = async (ssid) => {
    try {
      await api.removeFromWhitelist(ssid);
      await fetchData(); 
    } catch (err) {
      alert('Failed to remove from whitelist: ' + err.message);
    }
  };

  const handleDeleteBSSIDFromWhitelist = async (ssid, bssid) => {
    try {
      await api.removeBSSIDFromWhitelist(ssid, bssid);
      await fetchData(); 
    } catch (err) {
      alert('Failed to remove BSSID from whitelist: ' + err.message);
    }
  };

  const handleClearAlerts = async () => {
    try {
      await api.clearAlerts();
      await fetchData(); 
    } catch (err) {
      alert('Failed to clear alerts: ' + err.message);
    }
  };

  if (loading && !status) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4 text-blue-600" />
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center bg-white p-8 rounded-lg shadow-lg">
          <XCircle className="w-12 h-12 text-red-600 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-gray-800 mb-2">Connection Error</h2>
          <p className="text-gray-600 mb-4">Failed to connect to WiFi Monitor API</p>
          <p className="text-sm text-gray-500 mb-4">Error: {error}</p>
          <button
            onClick={fetchData}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">WiFi Security Monitor</h1>
            </div>
            <div className="flex items-center gap-4">
              <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm ${
                status?.is_running ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
              }`}>
                <div className={`w-2 h-2 rounded-full ${
                  status?.is_running ? 'bg-green-600' : 'bg-red-600'
                }`}></div>
                {status?.is_running ? 'Active' : 'Inactive'}
              </div>
              <button
                onClick={fetchData}
                className="p-2 text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                disabled={loading}
              >
                <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: Activity },
              { id: 'whitelist', label: 'Whitelist', icon: Shield },
              { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <StatusCard status={status} onRefresh={fetchData} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <NetworkList 
                networks={networks.filter(n => n.is_suspicious)} 
                onAddToWhitelist={handleAddToWhitelist}
                showOnlySuspicious={true}
              />
              <AlertsPanel alerts={alerts.slice(-10)} onClearAlerts={handleClearAlerts} />
            </div>
          </div>
        )}

        {activeTab === 'whitelist' && (
          <WhitelistManager
            whitelist={whitelist}
            onUpdate={handleUpdateWhitelist}
            onDelete={handleDeleteFromWhitelist}
            onDeleteBSSID={handleDeleteBSSIDFromWhitelist}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertsPanel alerts={alerts} onClearAlerts={handleClearAlerts} />
        )}
      </main>
    </div>
  );
};

export default WiFiMonitorDashboard;