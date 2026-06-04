/* ══════════════════════════════════════════════
   Godes OSINT Graph - Application Logic
   ══════════════════════════════════════════════ */

// ─── State ────────────────────────────────────

let network = null;
let nodesDataSet = null;
let edgesDataSet = null;
let allEntities = [];
let allRelationships = [];
let entityTypes = [];
let relationshipTypes = [];
let socialPlatforms = [];
let selectedNodeId = null;
let deleteCallback = null;
let searchTimeout = null;
let sortByDate = false;

// Entity type colors for graph nodes
const TYPE_COLORS = {
    person:           { background: '#065f46', border: '#6ee7b7', highlight: { background: '#047857', border: '#6ee7b7' } },
    email:            { background: '#1e3a5f', border: '#93c5fd', highlight: { background: '#1d4ed8', border: '#93c5fd' } },
    username:         { background: '#5c3d0e', border: '#fcd34d', highlight: { background: '#b45309', border: '#fcd34d' } },
    url:              { background: '#3b0764', border: '#c4b5fd', highlight: { background: '#6d28d9', border: '#c4b5fd' } },
    ip_address:       { background: '#5c0e0e', border: '#fca5a5', highlight: { background: '#b91c1c', border: '#fca5a5' } },
    company:          { background: '#0e3d5c', border: '#67e8f9', highlight: { background: '#0891b2', border: '#67e8f9' } },
    phone_number:     { background: '#5c280e', border: '#fdba74', highlight: { background: '#c2410c', border: '#fdba74' } },
    address:          { background: '#2d1f1a', border: '#d4a574', highlight: { background: '#57534e', border: '#d4a574' } },
    alias:            { background: '#3d0e5c', border: '#d8b4fe', highlight: { background: '#7e22ce', border: '#d8b4fe' } },
    social_media:     { background: '#4c0e3d', border: '#f9a8d4', highlight: { background: '#be185d', border: '#f9a8d4' } },
    domain:           { background: '#1f2d3a', border: '#94a3b8', highlight: { background: '#475569', border: '#94a3b8' } },
    cryptocurrency:   { background: '#3d4c0e', border: '#fde68a', highlight: { background: '#a16207', border: '#fde68a' } },
    organization:     { background: '#0e2d4c', border: '#7dd3fc', highlight: { background: '#0369a1', border: '#7dd3fc' } },
    device:           { background: '#2d1f2d', border: '#c4b5fd', highlight: { background: '#6b21a8', border: '#c4b5fd' } },
    location:         { background: '#1a2d1a', border: '#86efac', highlight: { background: '#15803d', border: '#86efac' } },
    other:            { background: '#1f2937', border: '#9ca3af', highlight: { background: '#4b5563', border: '#9ca3af' } },
};


// ══════════════════════════════════════════════
//  API
// ══════════════════════════════════════════════

const API = {
    async get(url) {
        const res = await fetch(url);
        return res.json();
    },
    async post(url, data) {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        return res.json();
    },
    async put(url, data) {
        const res = await fetch(url, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        return res.json();
    },
    async del(url) {
        const res = await fetch(url, { method: 'DELETE' });
        return res.json();
    },
    getEntities(search, type, platform) {
        const params = new URLSearchParams();
        if (search) params.set('search', search);
        if (type && type !== 'all') params.set('type', type);
        if (platform) params.set('platform', platform);
        return this.get(`/api/entities?${params}`);
    },
    createEntity(data) { return this.post('/api/entities', data); },
    updateEntity(id, data) { return this.put(`/api/entities/${id}`, data); },
    deleteEntity(id) { return this.del(`/api/entities/${id}`); },
    enrichEntity(id) { return this.post(`/api/enrich/${id}`, {}); },
    getGraph() { return this.get('/api/graph'); },
    getRelationships() { return this.get('/api/relationships'); },
    createRelationship(data) { return this.post('/api/relationships', data); },
    deleteRelationship(id) { return this.del(`/api/relationships/${id}`); },
    getTypes() { return this.get('/api/types'); },
    uploadImage(file) {
        const formData = new FormData();
        formData.append('file', file);
        return fetch('/api/upload', { method: 'POST', body: formData }).then(r => r.json());
    },
    bulkImport(data) { return this.post('/api/bulk-import', data); },
    bulkEnrich() { return this.post('/api/bulk-enrich', {}); },
    exportGraph() { return this.get('/api/export'); },
};


// ══════════════════════════════════════════════
//  Graph Initialization
// ══════════════════════════════════════════════

function initGraph() {
    const container = document.getElementById('graph');

    nodesDataSet = new vis.DataSet([]);
    edgesDataSet = new vis.DataSet([]);

    const options = {
        nodes: {
            shape: 'dot',
            size: 25,
            font: {
                size: 13,
                face: '-apple-system, BlinkMacSystemFont, sans-serif',
                color: '#e2e8f0',
                strokeWidth: 2,
                strokeColor: '#0a0e17',
            },
            borderWidth: 2,
            shadow: { enabled: true, size: 4, x: 0, y: 0 },
        },
        edges: {
            width: 2,
            color: { color: '#1e3a5f', highlight: '#3b82f6', hover: '#3b82f6' },
            selectionWidth: 3,
            smooth: { type: 'continuous', roundness: 0.4 },
            font: {
                size: 11,
                face: '-apple-system, BlinkMacSystemFont, sans-serif',
                color: '#94a3b8',
                strokeWidth: 2,
                strokeColor: '#0a0e17',
                align: 'middle',
            },
            arrows: { to: { enabled: true, scaleFactor: 0.6 } },
        },
        physics: {
            stabilization: { iterations: 150 },
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -40,
                centralGravity: 0.005,
                springLength: 180,
                springConstant: 0.02,
                damping: 0.4,
            },
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            navigationButtons: false,
            keyboard: true,
            multiselect: false,
        },
        groups: buildGroups(),
    };

    network = new vis.Network(container, { nodes: nodesDataSet, edges: edgesDataSet }, options);

    network.on('click', function (params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            selectNode(nodeId);
        } else {
            deselectNode();
        }
    });

    network.on('doubleClick', function (params) {
        if (params.nodes.length > 0) {
            openEditEntityModal(params.nodes[0]);
        }
    });

    network.on('hoverNode', function (params) {
        document.getElementById('graph').style.cursor = 'pointer';
    });

    network.on('blurNode', function () {
        document.getElementById('graph').style.cursor = 'default';
    });

    // Handle window resize
    window.addEventListener('resize', () => {
        network && network.fit({ animation: { duration: 300 } });
    });
}

function buildGroups() {
    const groups = {};
    for (const [type, colors] of Object.entries(TYPE_COLORS)) {
        groups[type] = {
            color: colors,
            shape: 'dot',
        };
    }
    return groups;
}


// ══════════════════════════════════════════════
//  Data Loading
// ══════════════════════════════════════════════

async function loadGraph() {
    try {
        const [graphData, typesData] = await Promise.all([
            API.getGraph(),
            API.getTypes(),
        ]);

        entityTypes = typesData.entity_types;
        relationshipTypes = typesData.relationship_types;
        socialPlatforms = typesData.social_platforms;
        allEntities = graphData.nodes;
        allRelationships = graphData.edges;

        // Check if we need the search filter
        const searchTerm = document.getElementById('searchInput').value.toLowerCase().trim();
        const typeFilter = document.getElementById('typeFilter').value;
        const platformFilter = document.getElementById('platformFilter').value;

        // Show/hide platform filter based on type selection
        const pf = document.getElementById('platformFilter');
        pf.style.display = (typeFilter === 'social_media') ? 'block' : 'none';

        // If there are filters, filter the entities for the graph
        let filteredEntityIds = null;
        if (searchTerm || (typeFilter && typeFilter !== 'all') || platformFilter) {
            const entitiesRes = await API.getEntities(searchTerm, typeFilter, platformFilter);
            filteredEntityIds = new Set(entitiesRes.map(e => e.id));
        }

        // Update graph
        const nodes = graphData.nodes.map(n => ({
            id: n.id,
            label: n.label,
            title: buildNodeTooltip(n),
            group: n.group,
            size: calcNodeSize(n.id, graphData.edges),
            color: TYPE_COLORS[n.group] || TYPE_COLORS.other,
            borderWidth: 2,
        }));

        const edges = graphData.edges.map(e => ({
            id: e.id,
            from: e.from,
            to: e.to,
            label: e.relationship_type.replace(/_/g, ' '),
            title: e.title,
            color: { color: '#1e3a5f', highlight: '#3b82f6' },
            width: 2,
        }));

        nodesDataSet.clear();
        edgesDataSet.clear();

        // If filtering, only add nodes/edges that match
        if (filteredEntityIds) {
            const filteredNodes = nodes.filter(n => filteredEntityIds.has(n.id));
            const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
            const filteredEdges = edges.filter(e =>
                filteredNodeIds.has(e.from) && filteredNodeIds.has(e.to)
            );
            nodesDataSet.add(filteredNodes);
            edgesDataSet.add(filteredEdges);
        } else {
            nodesDataSet.add(nodes);
            edgesDataSet.add(edges);
        }

        // Update sidebar
        updateEntityList();
        updateStats();
        updateTypeFilterOptions();
        updatePlatformFilterOptions();

        // Show/hide empty state
        const emptyState = document.getElementById('emptyState');
        if (nodesDataSet.length === 0) {
            emptyState.style.display = 'block';
            document.getElementById('graph').style.display = 'none';
        } else {
            emptyState.style.display = 'none';
            document.getElementById('graph').style.display = 'block';
            network.fit({ animation: { duration: 500 } });
        }

    } catch (err) {
        console.error('Failed to load graph:', err);
        showToast('Failed to load graph data', 'error');
    }
}

function calcNodeSize(nodeId, edges) {
    const connections = edges.filter(e => e.from === nodeId || e.to === nodeId).length;
    return Math.max(18, Math.min(45, 18 + connections * 4));
}

function buildNodeTooltip(node) {
    let html = `<b>${escapeHtml(node.label)}</b><br>`;
    html += `Type: ${node.entity_type.replace(/_/g, ' ')}`;
    if (node.platform) {
        html += `<br>Platform: ${node.platform.charAt(0).toUpperCase() + node.platform.slice(1)}`;
    }
    if (node.notes) {
        const truncated = node.notes.length > 120 ? node.notes.substring(0, 120) + '...' : node.notes;
        html += `<br><br>${escapeHtml(truncated)}`;
    }
    return html;
}


// ══════════════════════════════════════════════
//  Entity List (Sidebar)
// ══════════════════════════════════════════════

function updateEntityList() {
    const container = document.getElementById('entityList');
    const searchTerm = document.getElementById('searchInput').value.toLowerCase().trim();

    let filtered = allEntities;
    if (searchTerm) {
        filtered = filtered.filter(e =>
            e.label.toLowerCase().includes(searchTerm) ||
            (e.notes && e.notes.toLowerCase().includes(searchTerm)) ||
            (e.tags && e.tags.toLowerCase().includes(searchTerm))
        );
    }

    if (filtered.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 40px 20px; color: var(--text-muted); font-size: 13px;">
                ${searchTerm ? 'No entities match your search.' : 'No entities yet. Add one to get started!'}
            </div>
        `;
        return;
    }

    // Sort
    const sorted = [...filtered].sort((a, b) => {
        if (sortByDate) {
            return (b.created_at || '').localeCompare(a.created_at || '');
        }
        const connA = allRelationships.filter(r => r.from === a.id || r.to === a.id).length;
        const connB = allRelationships.filter(r => r.from === b.id || r.to === b.id).length;
        return connB - connA;
    });

    container.innerHTML = sorted.map(e => {
        const connCount = allRelationships.filter(r => r.from === e.id || r.to === e.id).length;
        const isActive = selectedNodeId === e.id;
        const platformLabel = e.platform ? e.platform.charAt(0).toUpperCase() + e.platform.slice(1) : '';
        return `
            <div class="entity-item ${isActive ? 'active' : ''}" onclick="selectNode(${e.id})" data-id="${e.id}">
                <div class="entity-info">
                    <div class="entity-name">${escapeHtml(e.label)}</div>
                    <div class="entity-meta">${e.entity_type.replace(/_/g, ' ')}${platformLabel ? ' · ' + platformLabel : ''}${e.tags ? ' · ' + escapeHtml(e.tags) : ''}</div>
                </div>
                ${connCount > 0 ? `<span class="entity-connections">${connCount} conn</span>` : ''}
            </div>
        `;
    }).join('');
}

function updateStats() {
    document.getElementById('entityCount').textContent = allEntities.length;
    document.getElementById('relCount').textContent = allRelationships.length;
}


// ══════════════════════════════════════════════
//  Type Filter
// ══════════════════════════════════════════════

function updateTypeFilterOptions() {
    const select = document.getElementById('typeFilter');
    const currentValue = select.value;

    // Only update if options have changed
    const existingOptions = new Set(Array.from(select.options).map(o => o.value));
    const needsUpdate = entityTypes.some(t => !existingOptions.has(t));

    if (needsUpdate) {
        select.innerHTML = '<option value="all">All Types</option>';
        for (const type of entityTypes) {
            const option = document.createElement('option');
            option.value = type;
            option.textContent = type.replace(/_/g, ' ');
            select.appendChild(option);
        }
        select.value = currentValue;
    }
}


// ══════════════════════════════════════════════
//  Node Selection & Detail Panel
// ══════════════════════════════════════════════

async function selectNode(nodeId) {
    selectedNodeId = nodeId;
    document.querySelectorAll('.entity-item').forEach(el => el.classList.remove('active'));
    const item = document.querySelector(`.entity-item[data-id="${nodeId}"]`);
    if (item) item.classList.add('active');

    // Highlight in graph
    network.selectNodes([nodeId]);
    network.focus(nodeId, { scale: 1.5, animation: { duration: 300 } });

    showEntityDetail(nodeId);
    document.getElementById('addRelBtn').disabled = false;
}

function deselectNode() {
    selectedNodeId = null;
    network.unselectAll();
    document.querySelectorAll('.entity-item').forEach(el => el.classList.remove('active'));
    closeDetailPanel();
    document.getElementById('addRelBtn').disabled = true;
}

async function showEntityDetail(nodeId) {
    const panel = document.getElementById('detailPanel');
    panel.classList.remove('hidden');

    const entity = allEntities.find(e => e.id === nodeId);
    if (!entity) return;

    const content = document.getElementById('detailContent');
    const title = document.getElementById('detailTitle');

    // Fetch full entity data
    const entities = await API.getEntities();
    const fullEntity = entities.find(e => e.id === nodeId);
    if (!fullEntity) return;

    title.textContent = fullEntity.name;

    // Get connections
    const rels = await API.getRelationships();
    const connections = rels.filter(r => r.source_id === nodeId || r.target_id === nodeId);

    const tags = fullEntity.tags ? fullEntity.tags.split(',').map(t => t.trim()).filter(Boolean) : [];

    // Parse JSON fields that come as strings from the API
    function tryParse(val) {
        if (!val) return [];
        if (typeof val !== 'string') return val;
        try { return JSON.parse(val); } catch { return []; }
    }
    const links = tryParse(fullEntity.links);
    const images = tryParse(fullEntity.images);

    const platform = fullEntity.platform || '';
    const profileUrl = fullEntity.profile_url || '';

    content.innerHTML = `
        <div class="detail-section">
            <span class="detail-type-badge type-${fullEntity.entity_type}">${fullEntity.entity_type.replace(/_/g, ' ')}</span>
            ${platform ? `<span class="detail-platform-badge">${escapeHtml(platform.charAt(0).toUpperCase() + platform.slice(1))}</span>` : ''}
        </div>

        ${profileUrl ? `
        <div class="detail-section">
            <h3>Profile Link</h3>
            <a href="${escapeHtml(profileUrl)}" target="_blank" rel="noopener" class="detail-link">
                <span class="detail-link-icon"></span>
                <span class="detail-link-text">${escapeHtml(profileUrl)}</span>
            </a>
        </div>
        ` : ''}

        ${fullEntity.notes ? `
        <div class="detail-section">
            <h3>Notes</h3>
            <p>${escapeHtml(fullEntity.notes)}</p>
        </div>
        ` : ''}

        ${links.length > 0 ? `
        <div class="detail-section">
            <h3>Links / URLs (${links.length})</h3>
            <div class="detail-links">
                ${links.map(l => `
                    <a href="${escapeHtml(l.url)}" target="_blank" rel="noopener" class="detail-link">
                        <span class="detail-link-icon"></span>
                        <span class="detail-link-text">${escapeHtml(l.title || l.url)}</span>
                    </a>
                `).join('')}
            </div>
        </div>
        ` : ''}

        ${images.length > 0 ? `
        <div class="detail-section">
            <h3>Images / Photos (${images.length})</h3>
            <div class="detail-images">
                ${images.map(img => `
                    <div class="detail-image-item">
                        <img src="${escapeHtml(img.url)}" alt="${escapeHtml(img.title || 'Image')}" loading="lazy" onclick="window.open('${escapeHtml(img.url)}', '_blank')">
                        <span class="detail-image-caption">${escapeHtml(img.title || 'Image')}</span>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        ${tags.length > 0 ? `
        <div class="detail-section">
            <h3>Tags</h3>
            <div class="detail-tags">
                ${tags.map(t => `<span class="detail-tag">${escapeHtml(t)}</span>`).join('')}
            </div>
        </div>
        ` : ''}

        <div class="detail-section">
            <h3>Connections (${connections.length})</h3>
            ${connections.length > 0 ? `
            <ul class="detail-connections-list">
                ${connections.map(r => {
                    const isSource = r.source_id === nodeId;
                    const other = isSource ? { name: r.target_name, id: r.target_id, type: r.target_type } : { name: r.source_name, id: r.source_id, type: r.source_type };
                    const arrow = isSource ? '→' : '←';
                    return `
                        <li onclick="selectNode(${other.id})" style="cursor:pointer;">
                            ${arrow} <strong>${escapeHtml(other.name)}</strong>
                            <span class="rel-type">${r.relationship_type.replace(/_/g, ' ')}</span>
                            <button class="btn-danger-sm" onclick="event.stopPropagation(); confirmDeleteRelationship(${r.id})"></button>
                        </li>
                    `;
                }).join('')}
            </ul>
            ` : '<p style="color: var(--text-muted); font-size: 13px;">No connections yet. Add one!</p>'}
        </div>

        <div class="detail-section" id="enrichResultSection" style="display:none;">
            <h3> Enrichment Results</h3>
            <div id="enrichResultContent"></div>
        </div>

        <div class="detail-actions">
            <button class="btn btn-primary btn-sm" onclick="enrichSelectedEntity(${nodeId})" id="enrichBtn">
                 Enrich
            </button>
            <button class="btn btn-secondary btn-sm" onclick="openEditEntityModal(${nodeId})">
                 Edit
            </button>
            <button class="btn btn-secondary btn-sm" onclick="openAddRelationshipModal(${nodeId})">
                 Add Connection
            </button>
            <button class="btn btn-danger btn-sm" onclick="confirmDeleteEntity(${nodeId})">
                 Delete
            </button>
        </div>
    `;
}

function closeDetailPanel() {
    document.getElementById('detailPanel').classList.add('hidden');
    document.getElementById('addRelBtn').disabled = true;
}


// ══════════════════════════════════════════════
//  Entity CRUD
// ══════════════════════════════════════════════

function openAddEntityModal() {
    document.getElementById('entityModalTitle').textContent = 'Add Entity';
    document.getElementById('editEntityId').value = '';
    document.getElementById('entityForm').reset();
    document.getElementById('entitySaveBtn').textContent = 'Save';
    document.getElementById('entityPlatform').value = '';
    document.getElementById('entityProfileUrl').value = '';
    populateEntityTypeSelect();
    // Reset links and images to one empty row each
    document.getElementById('linksContainer').innerHTML = '';
    document.getElementById('imagesContainer').innerHTML = '';
    addLinkRow();
    addImageRow();
    openModal('entityModal');
}

function openEditEntityModal(nodeId) {
    const entity = allEntities.find(e => e.id === nodeId);
    if (!entity) return;

    document.getElementById('entityModalTitle').textContent = 'Edit Entity';
    document.getElementById('editEntityId').value = nodeId;
    document.getElementById('entityName').value = entity.label || '';
    document.getElementById('entityNotes').value = entity.notes || '';
    document.getElementById('entityTags').value = entity.tags || '';
    document.getElementById('entityPlatform').value = entity.platform || '';
    document.getElementById('entityProfileUrl').value = entity.profile_url || '';
    document.getElementById('entitySaveBtn').textContent = 'Update';
    populateEntityTypeSelect(entity.entity_type);
    populateLinksForm(entity.links);
    populateImagesForm(entity.images);

    openModal('entityModal');
}

function populateEntityTypeSelect(selected) {
    const select = document.getElementById('entityType');
    select.innerHTML = entityTypes.map(t =>
        `<option value="${t}" ${t === selected ? 'selected' : ''}>${t.replace(/_/g, ' ')}</option>`
    ).join('');
    onEntityTypeChange();
}

function populatePlatformSelect(selected) {
    const select = document.getElementById('entityPlatform');
    select.innerHTML = socialPlatforms.map(p =>
        `<option value="${p}" ${p === selected ? 'selected' : ''}>${p.charAt(0).toUpperCase() + p.slice(1)}</option>`
    ).join('');
}


// ─── Links & Images Form Helpers ─────────────────

function getLinksFromForm() {
    const rows = document.querySelectorAll('#linksContainer .media-input-row');
    const links = [];
    rows.forEach(row => {
        const title = row.querySelector('.link-title').value.trim();
        const url = row.querySelector('.link-url').value.trim();
        if (url) {
            links.push({ title: title || url, url });
        }
    });
    return links;
}

function getImagesFromForm() {
    const rows = document.querySelectorAll('#imagesContainer .media-input-row');
    const images = [];
    rows.forEach(row => {
        const title = row.querySelector('.image-title').value.trim();
        const url = row.querySelector('.image-url').value.trim();
        if (url) {
            images.push({ title: title || 'Image', url });
        }
    });
    return images;
}

function populateLinksForm(links) {
    const container = document.getElementById('linksContainer');
    container.innerHTML = '';
    if (!links || links.length === 0) {
        // Add one empty row
        addLinkRow();
        return;
    }
    links.forEach(link => {
        const row = document.createElement('div');
        row.className = 'media-input-row';
        row.innerHTML = `
            <input type="text" class="link-title" placeholder="Label (e.g. TikTok profile)" value="${escapeHtml(link.title || '')}">
            <input type="url" class="link-url" placeholder="https://tiktok.com/@..." value="${escapeHtml(link.url || '')}">
            <button type="button" class="btn-icon-sm" onclick="removeLinkRow(this)" title="Remove link"></button>
        `;
        container.appendChild(row);
    });
}

function populateImagesForm(images) {
    const container = document.getElementById('imagesContainer');
    container.innerHTML = '';
    if (!images || images.length === 0) {
        addImageRow();
        return;
    }
    images.forEach(img => {
        const row = document.createElement('div');
        row.className = 'media-input-row';
        row.innerHTML = `
            <input type="text" class="image-title" placeholder="Description (e.g. Profile photo)" value="${escapeHtml(img.title || '')}">
            <input type="url" class="image-url" placeholder="https://example.com/photo.jpg" value="${escapeHtml(img.url || '')}">
            <button type="button" class="btn-icon-sm" onclick="removeImageRow(this)" title="Remove image"></button>
        `;
        container.appendChild(row);
    });
}

function addLinkRow() {
    const container = document.getElementById('linksContainer');
    const row = document.createElement('div');
    row.className = 'media-input-row';
    row.innerHTML = `
        <input type="text" class="link-title" placeholder="Label (e.g. TikTok profile)">
        <input type="url" class="link-url" placeholder="https://tiktok.com/@...">
        <button type="button" class="btn-icon-sm" onclick="removeLinkRow(this)" title="Remove link"></button>
    `;
    container.appendChild(row);
}

function addImageRow() {
    const container = document.getElementById('imagesContainer');
    const row = document.createElement('div');
    row.className = 'media-input-row';
    row.innerHTML = `
        <input type="text" class="image-title" placeholder="Description (e.g. Profile photo)">
        <input type="url" class="image-url" placeholder="https://example.com/photo.jpg">
        <button type="button" class="btn-icon-sm" onclick="removeImageRow(this)" title="Remove image"></button>
    `;
    container.appendChild(row);
}

function removeLinkRow(btn) {
    const row = btn.closest('.media-input-row');
    row.remove();
}

function removeImageRow(btn) {
    const row = btn.closest('.media-input-row');
    row.remove();
}


async function saveEntity(event) {
    event.preventDefault();

    const id = document.getElementById('editEntityId').value;
    const autoEnrich = document.getElementById('autoEnrichCheck').checked;
    const data = {
        name: document.getElementById('entityName').value.trim(),
        entity_type: document.getElementById('entityType').value,
        notes: document.getElementById('entityNotes').value.trim(),
        tags: document.getElementById('entityTags').value.trim(),
        links: getLinksFromForm(),
        images: getImagesFromForm(),
        platform: document.getElementById('entityPlatform').value || '',
        profile_url: document.getElementById('entityProfileUrl').value.trim() || '',
        auto_enrich: !id && autoEnrich,
    };

    try {
        if (id) {
            await API.updateEntity(id, data);
            showToast('Entity updated successfully', 'success');
        } else {
            await API.createEntity(data);
            showToast('Entity added successfully', 'success');
        }

        closeModal('entityModal');
        await loadGraph();
    } catch (err) {
        showToast('Failed to save entity', 'error');
    }
}

function confirmDeleteEntity(nodeId) {
    const entity = allEntities.find(e => e.id === nodeId);
    document.getElementById('deleteMessage').textContent =
        `Delete "${entity ? entity.label : 'this entity'}" and all its connections?`;
    document.getElementById('confirmDeleteBtn').onclick = async () => {
        try {
            await API.deleteEntity(nodeId);
            // Clear selection immediately to avoid stale UI
            if (selectedNodeId === nodeId) {
                selectedNodeId = null;
                closeDetailPanel();
            }
            closeModal('deleteModal');
            showToast('Entity deleted', 'success');
            await loadGraph();
        } catch (err) {
            showToast('Failed to delete entity', 'error');
        }
    };
    openModal('deleteModal');
}


// ══════════════════════════════════════════════
//  Relationship CRUD
// ══════════════════════════════════════════════

function openAddRelationshipModal(preSelectedId) {
    populateRelationshipDropdowns(preSelectedId);
    populateRelationshipTypeSelect();
    document.getElementById('relForm').reset();

    if (preSelectedId) {
        document.getElementById('relSource').value = preSelectedId;
    }

    openModal('relModal');
}

function populateRelationshipDropdowns(preSelectedId) {
    const sourceSelect = document.getElementById('relSource');
    const targetSelect = document.getElementById('relTarget');

    const options = allEntities
        .sort((a, b) => a.label.localeCompare(b.label))
        .map(e =>
            `<option value="${e.id}" ${e.id === preSelectedId ? 'selected' : ''}>${escapeHtml(e.label)} (${e.entity_type.replace(/_/g, ' ')})</option>`
        ).join('');

    sourceSelect.innerHTML = '<option value="">Select source...</option>' + options;
    targetSelect.innerHTML = '<option value="">Select target...</option>' + options;
}

function populateRelationshipTypeSelect(selected) {
    const select = document.getElementById('relType');
    select.innerHTML = relationshipTypes.map(t =>
        `<option value="${t}" ${t === selected ? 'selected' : ''}>${t.replace(/_/g, ' ')}</option>`
    ).join('');
}

async function saveRelationship(event) {
    event.preventDefault();

    const sourceId = parseInt(document.getElementById('relSource').value);
    const targetId = parseInt(document.getElementById('relTarget').value);

    if (sourceId === targetId) {
        showToast('Cannot connect an entity to itself', 'error');
        return;
    }

    const data = {
        source_id: sourceId,
        target_id: targetId,
        relationship_type: document.getElementById('relType').value,
        notes: document.getElementById('relNotes').value.trim(),
    };

    try {
        await API.createRelationship(data);
        closeModal('relModal');
        showToast('Connection added successfully', 'success');
        await loadGraph();

        // Re-select the node if one was selected
        if (selectedNodeId) {
            showEntityDetail(selectedNodeId);
        }
    } catch (err) {
        showToast('Failed to add connection', 'error');
    }
}

function confirmDeleteRelationship(relId) {
    const rel = allRelationships.find(r => r.id === relId);
    document.getElementById('deleteMessage').textContent =
        'Delete this connection?';
    document.getElementById('confirmDeleteBtn').onclick = async () => {
        try {
            await API.deleteRelationship(relId);
            closeModal('deleteModal');
            showToast('Connection removed', 'success');
            await loadGraph();
            if (selectedNodeId) {
                showEntityDetail(selectedNodeId);
            }
        } catch (err) {
            showToast('Failed to delete connection', 'error');
        }
    };
    openModal('deleteModal');
}


// ══════════════════════════════════════════════
//  OSINT Enrichment
// ══════════════════════════════════════════════

async function enrichSelectedEntity(nodeId) {
    const btn = document.getElementById('enrichBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = ' Enriching...';
    btn.disabled = true;

    try {
        const result = await API.enrichEntity(nodeId);

        if (result.error) {
            showToast('Enrichment failed: ' + result.error, 'error');
            return;
        }

        // Show enrichment results in the detail panel
        const section = document.getElementById('enrichResultSection');
        const content = document.getElementById('enrichResultContent');

        let html = '';

        // Intel items
        if (result.intel && result.intel.length > 0) {
            html += '<div class="enrich-intel">';
            result.intel.forEach(item => {
                const val = String(item.value);
                html += `<div class="enrich-intel-item">
                    <span class="enrich-intel-label">${escapeHtml(item.label)}</span>
                    <span class="enrich-intel-value">${escapeHtml(val)}</span>
                </div>`;
            });
            html += '</div>';
        }

        // OSINT Links
        if (result.links && result.links.length > 0) {
            html += '<h4 style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin:12px 0 6px;">OSINT Lookup Links</h4>';
            html += '<div class="enrich-links">';
            result.links.forEach(link => {
                html += `<a href="${escapeHtml(link.url)}" target="_blank" rel="noopener" class="enrich-link">
                    <span></span>
                    <span>${escapeHtml(link.title)}</span>
                </a>`;
            });
            html += '</div>';
        }

        content.innerHTML = html || '<p style="color:var(--text-muted);font-size:13px;">No enrichment data found for this entity type.</p>';
        section.style.display = 'block';

        // Refresh the detail panel data (notes/links/tags were saved) but keep enrich results visible
        showEntityDetail(nodeId).then(() => {
            // Re-show enrichment results after the detail panel refreshes
            const freshSection = document.getElementById('enrichResultSection');
            const freshContent = document.getElementById('enrichResultContent');
            if (freshSection && freshContent) {
                freshSection.style.display = 'block';
                freshContent.innerHTML = html;
            }
        });

        showToast('Enrichment complete! Check the results', 'success');
    } catch (err) {
        showToast('Enrichment failed: ' + err.message, 'error');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}


// ══════════════════════════════════════════════
//  Sort Toggle
// ══════════════════════════════════════════════

function toggleSort() {
    sortByDate = !sortByDate;
    document.getElementById('sortIcon').textContent = sortByDate ? '' : '';
    document.getElementById('sortLabel').textContent = sortByDate ? 'by date' : 'by connections';
    updateEntityList();
}


// ══════════════════════════════════════════════
//  Platform Filter
// ══════════════════════════════════════════════

function onEntityTypeChange() {
    const type = document.getElementById('entityType').value;
    const socialFields = document.getElementById('socialFields');
    const platformFilter = document.getElementById('platformFilter');

    if (type === 'social_media') {
        socialFields.classList.remove('hidden');
        populatePlatformSelect(document.getElementById('entityPlatform').value || 'tiktok');
        platformFilter.style.display = 'block';
    } else {
        socialFields.classList.add('hidden');
        platformFilter.style.display = 'none';
    }
}

function updatePlatformFilterOptions() {
    const select = document.getElementById('platformFilter');
    const currentValue = select.value;
    select.innerHTML = '<option value="">All Platforms</option>';
    for (const p of socialPlatforms) {
        const opt = document.createElement('option');
        opt.value = p;
        opt.textContent = p.charAt(0).toUpperCase() + p.slice(1);
        select.appendChild(opt);
    }
    select.value = currentValue;
}


// ══════════════════════════════════════════════
//  Bulk Import
// ══════════════════════════════════════════════

function openBulkImportModal() {
    document.getElementById('bulkImportText').value = '';
    document.getElementById('bulkImportResults').style.display = 'none';
    document.getElementById('bulkImportType').value = 'auto';
    document.getElementById('bulkImportPlatformField').style.display = 'none';
    // Populate platform dropdown
    const platformSelect = document.getElementById('bulkImportPlatform');
    platformSelect.innerHTML = socialPlatforms.map(p =>
        `<option value="${p}">${p.charAt(0).toUpperCase() + p.slice(1)}</option>`
    ).join('');
    openModal('bulkImportModal');
}

// Show/hide platform field in bulk import based on type
if (document.getElementById('bulkImportType')) {
    document.getElementById('bulkImportType').addEventListener('change', function() {
        document.getElementById('bulkImportPlatformField').style.display =
            this.value === 'social_media' ? 'block' : 'none';
    });
}

async function bulkImport(event) {
    event.preventDefault();
    const btn = document.getElementById('bulkImportSubmitBtn');
    btn.disabled = true;
    btn.textContent = 'Importing...';

    try {
        const result = await API.bulkImport({
            lines: document.getElementById('bulkImportText').value,
            default_type: document.getElementById('bulkImportType').value === 'auto' ? 'url' : document.getElementById('bulkImportType').value,
            default_platform: document.getElementById('bulkImportPlatform').value || '',
        });

        const resultsDiv = document.getElementById('bulkImportResults');
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            <div style="padding:12px;background:var(--bg-tertiary);border-radius:var(--radius);margin-top:8px;">
                <p style="font-size:13px;margin-bottom:4px;"> Created <strong>${result.created}</strong> entities</p>
                ${result.errors > 0 ? `<p style="font-size:13px;color:var(--danger);"> ${result.errors} errors</p>` : ''}
            </div>
        `;

        await loadGraph();
        showToast(`Imported ${result.created} entities`, 'success');

        // Auto-enrich if checked
        if (document.getElementById('bulkAutoEnrich').checked && result.created > 0) {
            showToast('Enriching imported entities...', 'info');
            await bulkEnrichAll();
        }
    } catch (err) {
        showToast('Import failed: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Import';
    }
}


// ══════════════════════════════════════════════
//  Bulk Enrich
// ══════════════════════════════════════════════

async function bulkEnrichAll() {
    const btn = document.getElementById('bulkEnrichBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = ' Enriching...';
    btn.disabled = true;

    try {
        const result = await API.bulkEnrich();
        showToast(`Enriched ${result.enriched} entities (${result.skipped} skipped, ${result.errors} errors)`, 'success');
        await loadGraph();
    } catch (err) {
        showToast('Bulk enrich failed: ' + err.message, 'error');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}


// ══════════════════════════════════════════════
//  Export Graph
// ══════════════════════════════════════════════

async function exportGraph() {
    try {
        const data = await API.exportGraph();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `osint-graph-${new Date().toISOString().slice(0,10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast(`Exported ${data.entities.length} entities and ${data.relationships.length} connections`, 'success');
    } catch (err) {
        showToast('Export failed: ' + err.message, 'error');
    }
}


// ══════════════════════════════════════════════
//  Image Upload
// ══════════════════════════════════════════════

async function uploadImageButton() {
    // Reset and trigger file input
    const input = document.getElementById('imageUploadInput');
    input.value = '';
    input.click();
}

async function handleImageUpload(input) {
    const file = input.files[0];
    if (!file) return;

    // Show loading
    showToast('Uploading image...', 'info');

    try {
        const result = await API.uploadImage(file);
        if (result.error) {
            showToast('Upload failed: ' + result.error, 'error');
            return;
        }
        // Add the uploaded image as a new row
        const container = document.getElementById('imagesContainer');
        const row = document.createElement('div');
        row.className = 'media-input-row';
        row.innerHTML = `
            <input type="text" class="image-title" placeholder="Description" value="${file.name}">
            <input type="url" class="image-url" value="${result.url}" readonly>
            <button type="button" class="btn-icon-sm" onclick="removeImageRow(this)" title="Remove image"></button>
        `;
        container.appendChild(row);
        showToast('Image uploaded!', 'success');
    } catch (err) {
        showToast('Upload failed: ' + err.message, 'error');
    }
}


// ══════════════════════════════════════════════
//  Search
// ══════════════════════════════════════════════

function debounceSearch() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        loadGraph();
    }, 300);
}


// ══════════════════════════════════════════════
//  Graph Controls
// ══════════════════════════════════════════════

function resetView() {
    if (network) {
        network.fit({ animation: { duration: 500 } });
    }
}


// ══════════════════════════════════════════════
//  Modal Helpers
// ══════════════════════════════════════════════

function openModal(id) {
    document.getElementById(id).classList.remove('hidden');
}

function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
}

// Close modals on backdrop click
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay') && !e.target.classList.contains('hidden')) {
        e.target.classList.add('hidden');
    }
});

// Close modals on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay:not(.hidden)').forEach(m => m.classList.add('hidden'));
    }
});


// ══════════════════════════════════════════════
//  Toast Notifications
// ══════════════════════════════════════════════

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');

    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}


// ══════════════════════════════════════════════
//  Utility
// ══════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}


// ══════════════════════════════════════════════
//  Init
// ══════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
    initGraph();
    await loadGraph();

    // Auto-fit after physics stabilizes
    network.on('stabilized', () => {
        network.fit({ animation: { duration: 300 } });
    });
});
