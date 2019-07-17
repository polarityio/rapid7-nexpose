let tagId = 2; // high is the first tag in the list, so we let it default

polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    selfLink: Ember.computed('block.data.details', function () {
        return this.get('block.data.details').links.filter(function (link) {
            return link.rel === 'self';
        }).pop();
    }),
    tagsLink: Ember.computed('block.data.details', function () {
        return this.get('block.data.details').links.filter(function (link) {
            return link.rel === 'Tags';
        }).pop();
    }),
    actions: {
        applyTag: function (assetId) {
            let self = this;
            let tagsLink = self.get('tagsLink');

            this.sendIntegrationMessage({ type: 'applyTag', assetId: assetId, tagId: tagId, tagsLink: tagsLink.href })
                .then((tags) => {
                    console.log('tag successfully added', tags);
                    
                    let details = self.get('block.data.details')
                    details.appliedTags = tags;

                    self.set('block.data.details', details);
                    self.notifyPropertyChange('block.data.details');
                })
                .catch(err => {
                    console.error('error applying tag', err);

                    // TODO display error message
                });
        },
        rescanSite: function(scanId) {
            let self = this;

            this.sendIntegrationMessage({type: 'rescanSite', scanId: scanId})
                .then(() => {
                    // TODO indicate on ui
                })
                .catch(err => {
                    console.error(err);
                });
        },
        onSelectTag: function (value) {
            tagId = value;
        }
    }
});
